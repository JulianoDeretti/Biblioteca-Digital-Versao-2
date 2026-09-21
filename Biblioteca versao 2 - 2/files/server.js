const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = 3000;
const DB_PATH = path.join(__dirname, 'db.json');

// ══════════════════════════════════════
// CONFIGURAÇÃO DE AUTENTICAÇÃO (FUNCIONÁRIO)
// ══════════════════════════════════════
// A senha agora vive SOMENTE no servidor (nunca é enviada ao navegador).
// Em produção, prefira variável de ambiente: process.env.SENHA_FUNCIONARIO
const SENHA_FUNCIONARIO = process.env.SENHA_FUNCIONARIO || 'adm001';
const TOKEN_DURACAO_MS = 2 * 60 * 60 * 1000; // 2 horas
const MAX_TENTATIVAS = 3;
const BLOQUEIO_MS = 30 * 1000; // 30 segundos
const PRAZO_EMPRESTIMO_DIAS = 14;

// tokens ativos: token -> timestamp de expiração
const sessoesAtivas = new Map();
// controle de tentativas de login por IP (proteção real, no servidor)
const tentativasPorIp = new Map(); // ip -> { tentativas, bloqueadoAte }

function limparSessoesExpiradas() {
    const agora = Date.now();
    for (const [token, expiraEm] of sessoesAtivas.entries()) {
        if (expiraEm < agora) sessoesAtivas.delete(token);
    }
}
setInterval(limparSessoesExpiradas, 5 * 60 * 1000);

function requireAuthFuncionario(req, res, next) {
    const token = req.headers['x-auth-token'];
    const expiraEm = token && sessoesAtivas.get(token);

    if (!expiraEm || expiraEm < Date.now()) {
        return res.status(401).json({ erro: 'Não autorizado. Faça login como funcionário.' });
    }

    // renova a validade a cada uso (sessão "deslizante")
    sessoesAtivas.set(token, Date.now() + TOKEN_DURACAO_MS);
    next();
}

app.use(cors());
app.use(express.json());

// ══════════════════════════════════════
// TRAVA DE ESCRITA (evita condição de corrida no banco em arquivo)
// ══════════════════════════════════════
// Sem isso, duas requisições simultâneas (ex.: dois usuários alugando o
// último exemplar de um livro ao mesmo tempo) podem ler o mesmo estado
// e ambas conseguirem "passar", furando o controle de estoque.
let filaDeEscrita = Promise.resolve();
function comTravaDeEscrita(tarefa) {
    const execucao = filaDeEscrita.then(() => tarefa());
    // garante que a fila continue mesmo se essa tarefa falhar
    filaDeEscrita = execucao.catch(() => {});
    return execucao;
}

// ══════════════════════════════════════
// FUNÇÕES AUXILIARES
// ══════════════════════════════════════

function lerDB() {
    try {
        if (!fs.existsSync(DB_PATH)) {
            const dbInicial = { books: [], rentals: [], history: [], readBooks: [] };
            fs.writeFileSync(DB_PATH, JSON.stringify(dbInicial, null, 2));
            return dbInicial;
        }
        const dados = fs.readFileSync(DB_PATH, 'utf-8');
        const db = JSON.parse(dados);
        db.books = db.books || [];
        db.rentals = db.rentals || [];
        db.history = db.history || [];
        db.readBooks = db.readBooks || [];
        return db;
    } catch (erro) {
        console.error('Erro ao ler banco de dados:', erro);
        return { books: [], rentals: [], history: [], readBooks: [] };
    }
}

function salvarDB(dados) {
    try {
        fs.writeFileSync(DB_PATH, JSON.stringify(dados, null, 2));
        return true;
    } catch (erro) {
        console.error('Erro ao salvar banco de dados:', erro);
        return false;
    }
}

function gerarId(array) {
    return array.length > 0 ? Math.max(...array.map(item => item.id)) + 1 : 1;
}

// Sanitização simples de string (defesa em profundidade contra XSS,
// complementando a proteção feita no frontend)
function limparTexto(valor, maxLen = 300) {
    if (typeof valor !== 'string') return '';
    return valor.replace(/[<>]/g, '').trim().slice(0, maxLen);
}

function urlDeImagemValida(valor) {
    if (typeof valor !== 'string' || valor.trim() === '') return false;
    try {
        const url = new URL(valor.trim());
        return url.protocol === 'http:' || url.protocol === 'https:';
    } catch {
        return false;
    }
}

const IMAGEM_PADRAO = 'https://via.placeholder.com/150x200?text=Sem+Imagem';

// ══════════════════════════════════════
// ENDPOINTS - AUTENTICAÇÃO
// ══════════════════════════════════════

app.post('/auth/login', (req, res) => {
    const ip = req.ip || req.connection.remoteAddress || 'desconhecido';
    const agora = Date.now();
    const registro = tentativasPorIp.get(ip) || { tentativas: 0, bloqueadoAte: 0 };

    if (registro.bloqueadoAte > agora) {
        const segundosRestantes = Math.ceil((registro.bloqueadoAte - agora) / 1000);
        return res.status(429).json({
            erro: `Muitas tentativas incorretas. Aguarde ${segundosRestantes} segundos.`,
            bloqueadoAte: registro.bloqueadoAte
        });
    }

    const { senha } = req.body;

    if (senha === SENHA_FUNCIONARIO) {
        tentativasPorIp.delete(ip);
        const token = crypto.randomBytes(32).toString('hex');
        sessoesAtivas.set(token, agora + TOKEN_DURACAO_MS);
        return res.json({ token, expiraEm: agora + TOKEN_DURACAO_MS });
    }

    registro.tentativas++;

    if (registro.tentativas >= MAX_TENTATIVAS) {
        registro.bloqueadoAte = agora + BLOQUEIO_MS;
        registro.tentativas = 0;
        tentativasPorIp.set(ip, registro);
        return res.status(429).json({
            erro: `Muitas tentativas incorretas. Aguarde ${BLOQUEIO_MS / 1000} segundos.`,
            bloqueadoAte: registro.bloqueadoAte
        });
    }

    tentativasPorIp.set(ip, registro);
    return res.status(401).json({
        erro: 'Senha incorreta',
        tentativasRestantes: MAX_TENTATIVAS - registro.tentativas
    });
});

app.post('/auth/logout', (req, res) => {
    const token = req.headers['x-auth-token'];
    if (token) sessoesAtivas.delete(token);
    res.json({ mensagem: 'Sessão encerrada' });
});

// Permite ao frontend verificar se um token salvo ainda é válido
app.get('/auth/verificar', requireAuthFuncionario, (req, res) => {
    res.json({ valido: true });
});

// ══════════════════════════════════════
// ENDPOINTS - BOOKS
// ══════════════════════════════════════

app.get('/books', (req, res) => {
    const db = lerDB();
    res.json(db.books || []);
});

app.get('/books/:id', (req, res) => {
    const db = lerDB();
    const id = parseInt(req.params.id);
    const livro = db.books.find(b => b.id === id);
    if (!livro) return res.status(404).json({ erro: 'Livro não encontrado' });
    res.json(livro);
});

// A partir daqui, apenas funcionários autenticados podem alterar o acervo
app.post('/books', requireAuthFuncionario, (req, res) => {
    comTravaDeEscrita(async () => {
        const { titulo, autor, estoque, imagem } = req.body;

        if (!titulo || titulo.trim() === '') {
            return res.status(400).json({ erro: 'Título é obrigatório' });
        }
        if (!autor || autor.trim() === '') {
            return res.status(400).json({ erro: 'Autor é obrigatório' });
        }

        const estoqueNum = Number(estoque);
        if (estoque === undefined || estoque === null || !Number.isInteger(estoqueNum) || estoqueNum < 0) {
            return res.status(400).json({ erro: 'Quantidade deve ser um número inteiro maior ou igual a zero' });
        }

        const db = lerDB();
        const novoLivro = {
            id: gerarId(db.books),
            titulo: limparTexto(titulo, 200),
            autor: limparTexto(autor, 150),
            estoque: estoqueNum,
            imagem: urlDeImagemValida(imagem) ? imagem.trim() : IMAGEM_PADRAO
        };

        db.books.push(novoLivro);

        if (salvarDB(db)) {
            res.status(201).json({ mensagem: 'Livro cadastrado com sucesso', livro: novoLivro });
        } else {
            res.status(500).json({ erro: 'Erro ao salvar livro' });
        }
    }).catch(erro => {
        console.error('Erro ao cadastrar livro:', erro);
        res.status(500).json({ erro: 'Erro interno ao cadastrar livro' });
    });
});

app.put('/books/:id', requireAuthFuncionario, (req, res) => {
    comTravaDeEscrita(async () => {
        const id = parseInt(req.params.id);
        const { titulo, autor, estoque, imagem } = req.body;

        const db = lerDB();
        const indice = db.books.findIndex(b => b.id === id);
        if (indice === -1) return res.status(404).json({ erro: 'Livro não encontrado' });

        if (estoque !== undefined) {
            const estoqueNum = Number(estoque);
            if (!Number.isInteger(estoqueNum) || estoqueNum < 0) {
                return res.status(400).json({ erro: 'Quantidade deve ser um número inteiro maior ou igual a zero' });
            }
        }
        if (titulo !== undefined && titulo.trim() === '') {
            return res.status(400).json({ erro: 'Título não pode ser vazio' });
        }
        if (autor !== undefined && autor.trim() === '') {
            return res.status(400).json({ erro: 'Autor não pode ser vazio' });
        }

        if (titulo !== undefined) db.books[indice].titulo = limparTexto(titulo, 200);
        if (autor !== undefined) db.books[indice].autor = limparTexto(autor, 150);
        if (estoque !== undefined) db.books[indice].estoque = Number(estoque);
        if (imagem !== undefined) {
            db.books[indice].imagem = urlDeImagemValida(imagem) ? imagem.trim() : IMAGEM_PADRAO;
        }

        if (salvarDB(db)) {
            res.json({ mensagem: 'Livro atualizado com sucesso', livro: db.books[indice] });
        } else {
            res.status(500).json({ erro: 'Erro ao atualizar livro' });
        }
    }).catch(erro => {
        console.error('Erro ao atualizar livro:', erro);
        res.status(500).json({ erro: 'Erro interno ao atualizar livro' });
    });
});

app.delete('/books/:id', requireAuthFuncionario, (req, res) => {
    comTravaDeEscrita(async () => {
        const id = parseInt(req.params.id);
        const db = lerDB();

        const alugueisAtivos = db.rentals.filter(r => r.livroId === id && !r.devolvido);
        if (alugueisAtivos.length > 0) {
            return res.status(400).json({ erro: 'Não é possível excluir livro com aluguéis ativos' });
        }

        const indice = db.books.findIndex(b => b.id === id);
        if (indice === -1) return res.status(404).json({ erro: 'Livro não encontrado' });

        db.books.splice(indice, 1);

        if (salvarDB(db)) {
            res.json({ mensagem: 'Livro excluído com sucesso' });
        } else {
            res.status(500).json({ erro: 'Erro ao excluir livro' });
        }
    }).catch(erro => {
        console.error('Erro ao excluir livro:', erro);
        res.status(500).json({ erro: 'Erro interno ao excluir livro' });
    });
});

// ══════════════════════════════════════
// ENDPOINTS - RENTALS
// ══════════════════════════════════════

app.get('/rentals', (req, res) => {
    const db = lerDB();
    // Retorna TODOS os rentals (neste banco, sempre os ativos —
    // aluguéis devolvidos são movidos para "history", ver DELETE abaixo)
    const alugueisComDetalhes = db.rentals.map(aluguel => {
        const livro = db.books.find(b => b.id === aluguel.livroId);
        return {
            ...aluguel,
            status: aluguel.status || 'lendo',
            livroTitulo: livro ? livro.titulo : 'Livro não encontrado',
            livroAutor: livro ? livro.autor : ''
        };
    });
    res.json(alugueisComDetalhes);
});

app.post('/rentals', (req, res) => {
    comTravaDeEscrita(async () => {
        const { livroId } = req.body;
        if (!livroId) return res.status(400).json({ erro: 'ID do livro é obrigatório' });

        const db = lerDB();
        const livro = db.books.find(b => b.id === parseInt(livroId));
        if (!livro) return res.status(404).json({ erro: 'Livro não encontrado' });
        if (livro.estoque <= 0) return res.status(400).json({ erro: 'Livro sem estoque disponível' });

        livro.estoque--;

        const agora = new Date();
        const vencimento = new Date(agora.getTime() + PRAZO_EMPRESTIMO_DIAS * 24 * 60 * 60 * 1000);

        const novoAluguel = {
            id: gerarId(db.rentals),
            livroId: parseInt(livroId),
            dataAluguel: agora.toISOString(),
            dataVencimento: vencimento.toISOString(),
            dataDevolucao: null,
            devolvido: false,
            status: 'lendo'
        };

        db.rentals.push(novoAluguel);

        if (salvarDB(db)) {
            res.status(201).json({
                mensagem: 'Livro alugado com sucesso',
                aluguel: { ...novoAluguel, livroTitulo: livro.titulo }
            });
        } else {
            res.status(500).json({ erro: 'Erro ao registrar aluguel' });
        }
    }).catch(erro => {
        console.error('Erro ao registrar aluguel:', erro);
        res.status(500).json({ erro: 'Erro interno ao registrar aluguel' });
    });
});

app.delete('/rentals/:id', (req, res) => {
    comTravaDeEscrita(async () => {
        const id = parseInt(req.params.id);
        const db = lerDB();
        const aluguel = db.rentals.find(r => r.id === id);
        if (!aluguel) return res.status(404).json({ erro: 'Aluguel não encontrado' });
        if (aluguel.devolvido) return res.status(400).json({ erro: 'Este aluguel já foi devolvido' });

        const livro = db.books.find(b => b.id === aluguel.livroId);
        if (!livro) return res.status(404).json({ erro: 'Livro não encontrado' });

        livro.estoque++;

        const dataDevolucao = new Date().toISOString();
        const registroHistorico = {
            id: gerarId(db.history),
            livroId: aluguel.livroId,
            livroTitulo: livro.titulo,
            livroAutor: livro.autor,
            status: 'concluído',
            dataAluguel: aluguel.dataAluguel,
            dataVencimento: aluguel.dataVencimento || null,
            dataDevolucao: dataDevolucao
        };

        db.history.push(registroHistorico);

        const indiceAluguel = db.rentals.findIndex(r => r.id === id);
        db.rentals.splice(indiceAluguel, 1);

        if (salvarDB(db)) {
            res.json({ mensagem: 'Livro devolvido com sucesso', historico: registroHistorico });
        } else {
            res.status(500).json({ erro: 'Erro ao registrar devolução' });
        }
    }).catch(erro => {
        console.error('Erro ao registrar devolução:', erro);
        res.status(500).json({ erro: 'Erro interno ao registrar devolução' });
    });
});

// ══════════════════════════════════════
// ENDPOINTS - HISTORY
// ══════════════════════════════════════

app.get('/history', (req, res) => {
    const db = lerDB();
    const historicoCompleto = db.history.map(item => {
        const livro = db.books.find(b => b.id === item.livroId);
        return {
            ...item,
            status: item.status || 'concluído',
            livroTitulo: livro ? livro.titulo : item.livroTitulo || 'Livro não encontrado',
            livroAutor: livro ? livro.autor : item.livroAutor || ''
        };
    });
    res.json(historicoCompleto);
});

app.post('/history', (req, res) => {
    comTravaDeEscrita(async () => {
        const { livroId, livroTitulo, livroAutor, status, dataAluguel, dataDevolucao } = req.body;
        const statusValidos = ['lendo', 'concluído', 'querendo'];
        const statusFinal = status && statusValidos.includes(status) ? status : 'concluído';

        const db = lerDB();
        let titulo = livroTitulo;
        let autor = livroAutor;

        if (livroId) {
            const livro = db.books.find(b => b.id === parseInt(livroId));
            if (livro) { titulo = livro.titulo; autor = livro.autor; }
        }

        const dataFinalDevolucao = dataDevolucao || new Date().toISOString();
        const novoHistorico = {
            id: gerarId(db.history),
            livroId: livroId ? parseInt(livroId) : null,
            livroTitulo: limparTexto(titulo || 'Sem título', 200),
            livroAutor: limparTexto(autor || 'Sem autor', 150),
            status: statusFinal,
            dataAluguel: dataAluguel || new Date().toISOString(),
            dataDevolucao: dataFinalDevolucao
        };

        db.history.push(novoHistorico);

        if (salvarDB(db)) {
            res.status(201).json({ mensagem: 'Adicionado ao histórico com sucesso', historico: novoHistorico });
        } else {
            res.status(500).json({ erro: 'Erro ao adicionar histórico' });
        }
    }).catch(erro => {
        console.error('Erro ao adicionar histórico:', erro);
        res.status(500).json({ erro: 'Erro interno ao adicionar histórico' });
    });
});

app.put('/history/:id', (req, res) => {
    comTravaDeEscrita(async () => {
        const id = parseInt(req.params.id);
        const { status, dataDevolucao } = req.body;

        const statusValidos = ['lendo', 'concluído', 'querendo'];
        if (status && !statusValidos.includes(status)) {
            return res.status(400).json({ erro: 'Status inválido. Use: lendo, concluído ou querendo' });
        }

        const db = lerDB();
        const indice = db.history.findIndex(h => h.id === id);
        if (indice === -1) return res.status(404).json({ erro: 'Registro de histórico não encontrado' });

        if (status) db.history[indice].status = status;
        if (dataDevolucao !== undefined) db.history[indice].dataDevolucao = dataDevolucao;

        if (salvarDB(db)) {
            res.json({ mensagem: 'Histórico atualizado com sucesso', historico: db.history[indice] });
        } else {
            res.status(500).json({ erro: 'Erro ao atualizar histórico' });
        }
    }).catch(erro => {
        console.error('Erro ao atualizar histórico:', erro);
        res.status(500).json({ erro: 'Erro interno ao atualizar histórico' });
    });
});

app.delete('/history/:id', (req, res) => {
    comTravaDeEscrita(async () => {
        const id = parseInt(req.params.id);
        const db = lerDB();
        const indice = db.history.findIndex(h => h.id === id);
        if (indice === -1) return res.status(404).json({ erro: 'Registro de histórico não encontrado' });

        db.history.splice(indice, 1);

        if (salvarDB(db)) {
            res.json({ mensagem: 'Registro removido do histórico com sucesso' });
        } else {
            res.status(500).json({ erro: 'Erro ao remover histórico' });
        }
    }).catch(erro => {
        console.error('Erro ao remover histórico:', erro);
        res.status(500).json({ erro: 'Erro interno ao remover histórico' });
    });
});

// ══════════════════════════════════════
// ENDPOINTS - READ BOOKS
// ══════════════════════════════════════

app.get('/readBooks', (req, res) => {
    const db = lerDB();
    res.json({ total: db.readBooks.length, livros: db.readBooks });
});

app.post('/readBooks', (req, res) => {
    comTravaDeEscrita(async () => {
        const { nome, autor } = req.body;
        if (!nome || nome.trim() === '') {
            return res.status(400).json({ erro: 'Nome do livro é obrigatório' });
        }

        const db = lerDB();
        const novoLivroLido = {
            id: gerarId(db.readBooks),
            nome: limparTexto(nome, 200),
            autor: autor && autor.trim() !== '' ? limparTexto(autor, 150) : 'Autor não informado',
            dataAdicao: new Date().toISOString()
        };

        db.readBooks.push(novoLivroLido);

        if (salvarDB(db)) {
            res.status(201).json({
                mensagem: 'Livro adicionado à lista de lidos com sucesso',
                livro: novoLivroLido,
                total: db.readBooks.length
            });
        } else {
            res.status(500).json({ erro: 'Erro ao adicionar livro lido' });
        }
    }).catch(erro => {
        console.error('Erro ao adicionar livro lido:', erro);
        res.status(500).json({ erro: 'Erro interno ao adicionar livro lido' });
    });
});

app.delete('/readBooks/:id', (req, res) => {
    comTravaDeEscrita(async () => {
        const id = parseInt(req.params.id);
        const db = lerDB();
        const indice = db.readBooks.findIndex(l => l.id === id);
        if (indice === -1) return res.status(404).json({ erro: 'Livro não encontrado na lista de lidos' });

        db.readBooks.splice(indice, 1);

        if (salvarDB(db)) {
            res.json({ mensagem: 'Livro removido da lista de lidos com sucesso', total: db.readBooks.length });
        } else {
            res.status(500).json({ erro: 'Erro ao remover livro lido' });
        }
    }).catch(erro => {
        console.error('Erro ao remover livro lido:', erro);
        res.status(500).json({ erro: 'Erro interno ao remover livro lido' });
    });
});

// ══════════════════════════════════════
// TRATAMENTO DE ROTA INEXISTENTE
// ══════════════════════════════════════
app.use((req, res) => {
    res.status(404).json({ erro: 'Rota não encontrada' });
});

// ══════════════════════════════════════
// INICIALIZAÇÃO DO SERVIDOR
// ══════════════════════════════════════

app.listen(PORT, () => {
    console.log('════════════════════════════════════════');
    console.log('  📚 BIBLIOTECA DIGITAL - SERVIDOR API');
    console.log('════════════════════════════════════════');
    console.log(`  ✅ Servidor rodando na porta ${PORT}`);
    console.log(`  🌐 URL: http://localhost:${PORT}`);
    console.log('════════════════════════════════════════');
});
