const API_URL = 'http://localhost:3000';
const PRAZO_EMPRESTIMO_DIAS = 14; // usado apenas como fallback para dados antigos sem dataVencimento

let modoAtual = 'usuario';
let livrosCache = [];
let alugueisCache = [];
let historicoCache = [];
let livrosLidosCache = [];

// Token de sessão do funcionário. Fica em memória + sessionStorage
// (não em localStorage) para não sobreviver além da aba/sessão do navegador.
let tokenFuncionario = sessionStorage.getItem('tokenFuncionario') || null;

// ══════════════════════════════════════
// SEGURANÇA - ESCAPE DE HTML (proteção contra XSS)
// ══════════════════════════════════════
// Todo conteúdo que vem do usuário/API é inserido via innerHTML neste app.
// Sem escapar, um título/autor/URL de imagem maliciosos poderiam injetar
// script na página. Esta função converte caracteres perigosos em entidades.
function escapeHtml(valor) {
    if (valor === null || valor === undefined) return '';
    return String(valor)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// Só aceita URLs http/https; qualquer outra coisa vira a imagem padrão.
// Evita, por exemplo, "javascript:" ou atributos quebrados no <img>.
function urlImagemSegura(valor) {
    const padrao = 'https://via.placeholder.com/150x200?text=Sem+Imagem';
    if (!valor || typeof valor !== 'string') return padrao;
    try {
        const url = new URL(valor);
        return (url.protocol === 'http:' || url.protocol === 'https:') ? valor : padrao;
    } catch {
        return padrao;
    }
}

// ══════════════════════════════════════
// NOTIFICAÇÕES (toast) - substitui alert() por algo não bloqueante
// ══════════════════════════════════════
function mostrarToast(mensagem, tipo = 'info') {
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.className = `toast toast-${tipo}`;
    toast.textContent = mensagem;
    container.appendChild(toast);

    requestAnimationFrame(() => toast.classList.add('toast-visivel'));

    setTimeout(() => {
        toast.classList.remove('toast-visivel');
        setTimeout(() => toast.remove(), 300);
    }, 3500);
}

// ══════════════════════════════════════
// INICIALIZAÇÃO
// ══════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
    inicializarEventos();
    restaurarEstadoAcordeoes();
    carregarModoInicial();
});

function inicializarEventos() {
    document.getElementById('btn-modo-usuario').addEventListener('click', () => alternarModo('usuario'));
    document.getElementById('btn-modo-funcionario').addEventListener('click', () => alternarModo('funcionario'));

    document.getElementById('form-login').addEventListener('submit', fazerLogin);
    document.getElementById('toggle-senha').addEventListener('change', toggleSenha);

    document.getElementById('form-buscar-livros').addEventListener('submit', buscarLivros);
    document.getElementById('form-adicionar-lido').addEventListener('submit', adicionarLivroLido);

    document.getElementById('form-adicionar-livro').addEventListener('submit', adicionarLivro);

    document.querySelectorAll('.accordion-titulo').forEach(titulo => {
        titulo.addEventListener('click', toggleAcordeon);
    });
}

function carregarModoInicial() {
    alternarModo('usuario');
}

// ══════════════════════════════════════
// CONTROLE DE MODOS
// ══════════════════════════════════════

async function alternarModo(modo) {
    modoAtual = modo;

    const loginFuncionario = document.getElementById('login-funcionario');
    const usuarioArea = document.getElementById('usuario-area');
    const funcionarioArea = document.getElementById('funcionario-area');

    const btnUsuario = document.getElementById('btn-modo-usuario');
    const btnFuncionario = document.getElementById('btn-modo-funcionario');

    if (modo === 'usuario') {
        loginFuncionario.classList.add('oculto');
        usuarioArea.classList.remove('oculto');
        funcionarioArea.classList.add('oculto');

        btnUsuario.classList.add('ativo');
        btnFuncionario.classList.remove('ativo');

        carregarDadosUsuario();
        return;
    }

    // Modo funcionário: se já existe um token válido nesta sessão, pula o login
    btnUsuario.classList.remove('ativo');
    btnFuncionario.classList.add('ativo');

    if (tokenFuncionario) {
        const valido = await verificarTokenFuncionario();
        if (valido) {
            loginFuncionario.classList.add('oculto');
            usuarioArea.classList.add('oculto');
            funcionarioArea.classList.remove('oculto');
            carregarDadosFuncionario();
            return;
        }
        // token expirado/inválido: limpa e cai para a tela de login
        tokenFuncionario = null;
        sessionStorage.removeItem('tokenFuncionario');
    }

    document.getElementById('mensagem-erro-login').textContent = '';
    document.querySelector('#form-login button[type="submit"]').disabled = false;

    loginFuncionario.classList.remove('oculto');
    usuarioArea.classList.add('oculto');
    funcionarioArea.classList.add('oculto');
}

async function verificarTokenFuncionario() {
    try {
        const response = await fetch(`${API_URL}/auth/verificar`, {
            headers: { 'x-auth-token': tokenFuncionario }
        });
        return response.ok;
    } catch {
        return false;
    }
}

// Cronômetro de bloqueio ativo (se houver), para não sobrepor intervalos
let intervaloBloqueio = null;

async function fazerLogin(e) {
    e.preventDefault();

    const senha = document.getElementById('senha-funcionario').value;
    const mensagemErro = document.getElementById('mensagem-erro-login');
    const btnEntrar = document.querySelector('#form-login button[type="submit"]');

    mensagemErro.textContent = '';
    btnEntrar.disabled = true;

    try {
        // A verificação da senha agora acontece no servidor — o navegador
        // nunca sabe qual é a senha correta.
        const response = await fetch(`${API_URL}/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ senha })
        });

        const dados = await response.json();

        if (response.ok) {
            tokenFuncionario = dados.token;
            sessionStorage.setItem('tokenFuncionario', tokenFuncionario);

            document.getElementById('login-funcionario').classList.add('oculto');
            document.getElementById('funcionario-area').classList.remove('oculto');
            document.getElementById('senha-funcionario').value = '';
            mensagemErro.textContent = '';
            btnEntrar.disabled = false;

            carregarDadosFuncionario();
            return;
        }

        if (response.status === 429) {
            // Bloqueado pelo servidor: mostra contagem regressiva real
            mensagemErro.style.color = '#c0392b';
            iniciarContagemBloqueio(dados.bloqueadoAte, mensagemErro, btnEntrar);
        } else {
            mensagemErro.style.color = '#c0392b';
            mensagemErro.textContent = dados.tentativasRestantes !== undefined
                ? `Senha incorreta. ${dados.tentativasRestantes} tentativa(s) restante(s)`
                : (dados.erro || 'Senha incorreta');
            btnEntrar.disabled = false;
        }
    } catch (erro) {
        console.error('Erro ao fazer login:', erro);
        mensagemErro.style.color = '#c0392b';
        mensagemErro.textContent = 'Não foi possível conectar ao servidor';
        btnEntrar.disabled = false;
    }
}

function iniciarContagemBloqueio(bloqueadoAte, mensagemErro, btnEntrar) {
    if (intervaloBloqueio) clearInterval(intervaloBloqueio);

    const atualizar = () => {
        const restante = Math.ceil((bloqueadoAte - Date.now()) / 1000);
        if (restante > 0) {
            mensagemErro.textContent = `Aguarde ${restante} segundos para tentar novamente`;
        } else {
            clearInterval(intervaloBloqueio);
            mensagemErro.textContent = 'Você já pode tentar novamente';
            mensagemErro.style.color = '#f39c12';
            btnEntrar.disabled = false;
        }
    };

    atualizar();
    intervaloBloqueio = setInterval(atualizar, 1000);
}

function toggleSenha(e) {
    const campoSenha = document.getElementById('senha-funcionario');
    campoSenha.type = e.target.checked ? 'text' : 'password';
}

// ══════════════════════════════════════
// ACORDEÃO
// ══════════════════════════════════════

function toggleAcordeon(e) {
    const titulo = e.currentTarget;
    const acordeonNome = titulo.dataset.accordion;
    const conteudo = titulo.nextElementSibling;

    const estaAberto = conteudo.classList.contains('aberto');

    if (estaAberto) {
        conteudo.classList.remove('aberto');
        salvarEstadoAcordeon(acordeonNome, false);
    } else {
        conteudo.classList.add('aberto');
        salvarEstadoAcordeon(acordeonNome, true);
    }
}

function salvarEstadoAcordeon(nome, aberto) {
    const estados = JSON.parse(localStorage.getItem('acordeoesAbertos') || '{}');
    estados[nome] = aberto;
    localStorage.setItem('acordeoesAbertos', JSON.stringify(estados));
}

function restaurarEstadoAcordeoes() {
    const estados = JSON.parse(localStorage.getItem('acordeoesAbertos') || '{}');

    Object.keys(estados).forEach(acordeonNome => {
        if (estados[acordeonNome]) {
            const titulo = document.querySelector(`[data-accordion="${acordeonNome}"]`);
            if (titulo) {
                const conteudo = titulo.nextElementSibling;
                conteudo.classList.add('aberto');
            }
        }
    });
}

// ══════════════════════════════════════
// UTILITÁRIO DE PRAZO DE DEVOLUÇÃO
// ══════════════════════════════════════

function calcularVencimento(aluguel) {
    if (aluguel.dataVencimento) return new Date(aluguel.dataVencimento);
    // fallback para aluguéis antigos, criados antes da vigência do prazo
    const base = new Date(aluguel.dataAluguel);
    base.setDate(base.getDate() + PRAZO_EMPRESTIMO_DIAS);
    return base;
}

function estaAtrasado(aluguel) {
    return calcularVencimento(aluguel).getTime() < Date.now();
}

// ══════════════════════════════════════
// MODO USUÁRIO - CARREGAR DADOS
// ══════════════════════════════════════

async function carregarDadosUsuario() {
    await carregarLivros();
    await carregarAlugueis();
    await carregarHistorico();
    await carregarLivrosLidos();
}

async function carregarLivros() {
    try {
        const response = await fetch(`${API_URL}/books`);
        livrosCache = await response.json();
    } catch (erro) {
        console.error('Erro ao carregar livros:', erro);
        livrosCache = [];
    }
}

async function carregarAlugueis() {
    try {
        const response = await fetch(`${API_URL}/rentals`);
        const todosAlugueis = await response.json();
        alugueisCache = todosAlugueis.filter(a => a.devolvido === false);
        renderizarAlugueis();
    } catch (erro) {
        console.error('Erro ao carregar aluguéis:', erro);
        alugueisCache = [];
        renderizarAlugueis();
    }
}

async function carregarHistorico() {
    try {
        const response = await fetch(`${API_URL}/history`);
        historicoCache = await response.json();
        renderizarHistorico();
    } catch (erro) {
        console.error('Erro ao carregar histórico:', erro);
        historicoCache = [];
        renderizarHistorico();
    }
}

async function carregarLivrosLidos() {
    try {
        const response = await fetch(`${API_URL}/readBooks`);
        if (!response.ok) throw new Error('Erro ao buscar livros lidos');

        const dados = await response.json();
        livrosLidosCache = (dados && typeof dados === 'object') ? (dados.livros || []) : [];
        renderizarLivrosLidos();
    } catch (erro) {
        console.error('Erro ao carregar livros lidos:', erro);
        livrosLidosCache = [];
        renderizarLivrosLidosErro();
    }
}

function renderizarLivrosLidosErro() {
    const total = document.getElementById('total-livros-lidos');
    const container = document.getElementById('lista-livros-lidos');
    total.textContent = '📖 Total de livros lidos: 0';
    container.innerHTML = '<p class="mensagem-erro">Erro ao carregar lista de livros lidos. Tente novamente mais tarde.</p>';
}

// ══════════════════════════════════════
// MODO USUÁRIO - BUSCAR LIVROS
// ══════════════════════════════════════

async function buscarLivros(e) {
    e.preventDefault();

    const termo = document.getElementById('busca-usuario').value.toLowerCase().trim();
    const container = document.getElementById('resultados-busca');

    if (termo === '') {
        container.innerHTML = '<p class="mensagem-info">Digite algo para buscar</p>';
        return;
    }

    container.innerHTML = '<p class="mensagem-info">Buscando...</p>';
    await carregarLivros();

    const resultados = livrosCache.filter(livro => {
        const titulo = livro.titulo.toLowerCase();
        const autor = livro.autor.toLowerCase();
        const codigo = livro.id.toString();
        return titulo.includes(termo) || autor.includes(termo) || codigo.includes(termo);
    });

    if (resultados.length === 0) {
        container.innerHTML = '<p class="mensagem-info">Nenhum livro encontrado</p>';
        return;
    }

    let html = '<div class="grid-livros">';

    resultados.forEach(livro => {
        const disponivel = livro.estoque > 0;
        const titulo = escapeHtml(livro.titulo);
        const autor = escapeHtml(livro.autor);
        const imagem = escapeHtml(urlImagemSegura(livro.imagem));

        html += `
            <div class="card-livro">
                <img src="${imagem}" alt="${titulo}" loading="lazy">
                <h4>${titulo}</h4>
                <p class="autor">${autor}</p>
                <p class="estoque ${disponivel ? 'disponivel' : 'indisponivel'}">
                    ${disponivel ? `${livro.estoque} disponível(is)` : 'Indisponível'}
                </p>
                ${disponivel ? `<button class="primario" onclick="alugarLivro(${livro.id})">Alugar</button>` : ''}
            </div>
        `;
    });

    html += '</div>';
    container.innerHTML = html;
}

async function alugarLivro(livroId) {
    try {
        const response = await fetch(`${API_URL}/rentals`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ livroId })
        });

        const dados = await response.json();

        if (response.ok) {
            mostrarToast('Livro alugado com sucesso!', 'sucesso');
            await carregarLivros();
            await carregarAlugueis();
            document.getElementById('form-buscar-livros').dispatchEvent(new Event('submit'));
        } else {
            mostrarToast(dados.erro || 'Erro ao alugar livro', 'erro');
        }
    } catch (erro) {
        console.error('Erro ao alugar livro:', erro);
        mostrarToast('Erro ao alugar livro', 'erro');
    }
}

// ══════════════════════════════════════
// MODO USUÁRIO - MEUS ALUGUÉIS
// ══════════════════════════════════════

function renderizarAlugueis() {
    const container = document.getElementById('lista-alugueis-usuario');

    if (alugueisCache.length === 0) {
        container.innerHTML = '<p class="mensagem-info">Você não possui livros alugados no momento</p>';
        return;
    }

    let html = '<div class="lista-alugueis">';

    alugueisCache.forEach(aluguel => {
        const status = aluguel.status || 'lendo';
        const dataAluguel = new Date(aluguel.dataAluguel).toLocaleDateString('pt-BR');
        const vencimento = calcularVencimento(aluguel);
        const atrasado = estaAtrasado(aluguel);
        const titulo = escapeHtml(aluguel.livroTitulo);
        const autor = escapeHtml(aluguel.livroAutor);

        html += `
            <div class="item-aluguel">
                <div class="info-aluguel">
                    <h4>${titulo}</h4>
                    <p>Autor: ${autor}</p>
                    <p>Alugado em: ${dataAluguel}</p>
                    <p>Devolver até: ${vencimento.toLocaleDateString('pt-BR')}
                        ${atrasado ? '<span class="badge badge-atrasado">Atrasado</span>' : ''}
                    </p>
                    <p>Status: <span class="badge badge-${status}">${escapeHtml(status)}</span></p>
                </div>
                <div class="acoes-aluguel">
                    <button class="secundario" onclick="devolverLivro(${aluguel.id})">Devolver</button>
                </div>
            </div>
        `;
    });

    html += '</div>';
    container.innerHTML = html;
}

async function devolverLivro(aluguelId) {
    if (!confirm('Deseja realmente devolver este livro?')) return;

    try {
        const response = await fetch(`${API_URL}/rentals/${aluguelId}`, { method: 'DELETE' });
        const dados = await response.json();

        if (response.ok) {
            mostrarToast('Livro devolvido com sucesso!', 'sucesso');
            await carregarAlugueis();
            await carregarHistorico();
            await carregarLivros();
        } else {
            mostrarToast(dados.erro || 'Erro ao devolver livro', 'erro');
        }
    } catch (erro) {
        console.error('Erro ao devolver livro:', erro);
        mostrarToast('Erro ao devolver livro', 'erro');
    }
}

// ══════════════════════════════════════
// MODO USUÁRIO - HISTÓRICO
// ══════════════════════════════════════
function renderizarHistorico() {
    const container = document.getElementById('historico-tabela');

    if (historicoCache.length === 0) {
        container.innerHTML = '<p class="mensagem-info">Seu histórico está vazio</p>';
        return;
    }

    let html = '<div class="tabela-historico">';
    html += '<table>';
    html += '<thead><tr><th>Livro</th><th>Autor</th><th>Alugado em</th><th>Devolvido em</th><th>Status</th><th>Ações</th></tr></thead>';
    html += '<tbody>';

    historicoCache.forEach(item => {
        const status = item.status || 'concluído';
        const dataAluguel = new Date(item.dataAluguel).toLocaleDateString('pt-BR');

        if (!item.dataDevolucao) {
            console.error('Item de histórico sem data de devolução:', item);
            return;
        }

        const dataDevolucao = new Date(item.dataDevolucao).toLocaleDateString('pt-BR');
        const titulo = escapeHtml(item.livroTitulo);
        const autor = escapeHtml(item.livroAutor);

        html += `
            <tr>
                <td>${titulo}</td>
                <td>${autor}</td>
                <td>${dataAluguel}</td>
                <td>${dataDevolucao}</td>
                <td><span class="badge badge-${status}">${escapeHtml(status)}</span></td>
                <td>
                    <select onchange="alterarStatusHistorico(${item.id}, this.value)" class="select-status">
                        <option value="">Alterar status</option>
                        <option value="lendo" ${status === 'lendo' ? 'selected' : ''}>Lendo</option>
                        <option value="concluído" ${status === 'concluído' ? 'selected' : ''}>Concluído</option>
                        <option value="querendo" ${status === 'querendo' ? 'selected' : ''}>Querendo</option>
                    </select>
                </td>
            </tr>
        `;
    });

    html += '</tbody></table></div>';
    container.innerHTML = html;
}

async function alterarStatusHistorico(historicoId, novoStatus) {
    if (!novoStatus) return;

    try {
        const response = await fetch(`${API_URL}/history/${historicoId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status: novoStatus })
        });

        const dados = await response.json();

        if (response.ok) {
            const indice = historicoCache.findIndex(h => h.id === historicoId);
            if (indice !== -1) historicoCache[indice].status = novoStatus;
            renderizarHistorico();
        } else {
            mostrarToast(dados.erro || 'Erro ao alterar status', 'erro');
            renderizarHistorico();
        }
    } catch (erro) {
        console.error('Erro ao alterar status:', erro);
        mostrarToast('Erro ao alterar status', 'erro');
        renderizarHistorico();
    }
}

// ══════════════════════════════════════
// MODO USUÁRIO - LIVROS LIDOS
// ══════════════════════════════════════
function renderizarLivrosLidos() {
    const total = document.getElementById('total-livros-lidos');
    const container = document.getElementById('lista-livros-lidos');

    total.textContent = `📖 Total de livros lidos: ${livrosLidosCache.length}`;

    if (livrosLidosCache.length === 0) {
        container.innerHTML = '<p class="mensagem-info">Você ainda não adicionou nenhum livro à lista</p>';
        return;
    }

    let html = '<div class="lista-livros-lidos">';

    livrosLidosCache.forEach(livro => {
        const nomeExibicao = escapeHtml(livro.nome || 'Sem título');
        const autorExibicao = escapeHtml(livro.autor || 'Autor não informado');

        html += `
            <div class="item-livro-lido">
                <div class="info-livro-lido">
                    <h4>${nomeExibicao}</h4>
                    <p>${autorExibicao}</p>
                </div>
                <button class="btn-remover" onclick="removerLivroLido(${livro.id})">✕</button>
            </div>
        `;
    });

    html += '</div>';
    container.innerHTML = html;
}

async function adicionarLivroLido(e) {
    e.preventDefault();

    const nome = document.getElementById('nome-livro-lido').value.trim();
    const autor = document.getElementById('autor-livro-lido').value.trim();

    if (!nome) {
        mostrarToast('Digite o nome do livro', 'erro');
        return;
    }

    try {
        const response = await fetch(`${API_URL}/readBooks`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ nome, autor })
        });

        if (response.ok) {
            document.getElementById('nome-livro-lido').value = '';
            document.getElementById('autor-livro-lido').value = '';
            await carregarLivrosLidos();
            mostrarToast('Livro adicionado à lista de lidos', 'sucesso');
        } else {
            const dados = await response.json();
            mostrarToast(dados.erro || 'Erro ao adicionar livro', 'erro');
        }
    } catch (erro) {
        console.error('Erro ao adicionar livro lido:', erro);
        mostrarToast('Erro ao adicionar livro', 'erro');
    }
}

async function removerLivroLido(livroId) {
    if (!confirm('Deseja realmente remover este livro da lista?')) return;

    try {
        const response = await fetch(`${API_URL}/readBooks/${livroId}`, { method: 'DELETE' });

        if (response.ok) {
            await carregarLivrosLidos();
        } else {
            const dados = await response.json();
            mostrarToast(dados.erro || 'Erro ao remover livro', 'erro');
        }
    } catch (erro) {
        console.error('Erro ao remover livro lido:', erro);
        mostrarToast('Erro ao remover livro', 'erro');
    }
}

// ══════════════════════════════════════
// MODO FUNCIONÁRIO - CARREGAR DADOS
// ══════════════════════════════════════

async function carregarDadosFuncionario() {
    await carregarAcervo();
    await carregarEmprestimos();
    await carregarHistorico();
    renderizarDashboardFuncionario();
}

async function carregarAcervo() {
    try {
        const response = await fetch(`${API_URL}/books`);
        livrosCache = await response.json();
        renderizarAcervo();
    } catch (erro) {
        console.error('Erro ao carregar acervo:', erro);
        livrosCache = [];
    }
}

async function carregarEmprestimos() {
    try {
        const response = await fetch(`${API_URL}/rentals`);
        const todosAlugueis = await response.json();
        alugueisCache = todosAlugueis;
        renderizarEmprestimos();
    } catch (erro) {
        console.error('Erro ao carregar empréstimos:', erro);
        alugueisCache = [];
    }
}

// ══════════════════════════════════════
// MODO FUNCIONÁRIO - DASHBOARD RÁPIDO
// ══════════════════════════════════════

function renderizarDashboardFuncionario() {
    let painel = document.getElementById('dashboard-funcionario');
    const areaFuncionario = document.getElementById('funcionario-area');

    if (!painel) {
        painel = document.createElement('div');
        painel.id = 'dashboard-funcionario';
        painel.className = 'dashboard-stats';
        areaFuncionario.insertBefore(painel, areaFuncionario.querySelector('h2').nextSibling);
    }

    const totalTitulos = livrosCache.length;
    const totalExemplares = livrosCache.reduce((soma, l) => soma + (Number(l.estoque) || 0), 0);
    const emprestimosAtivos = alugueisCache.filter(a => !a.devolvido).length;
    const atrasados = alugueisCache.filter(a => !a.devolvido && estaAtrasado(a)).length;

    painel.innerHTML = `
        <div class="stat-card">
            <span class="stat-numero">${totalTitulos}</span>
            <span class="stat-rotulo">Títulos no acervo</span>
        </div>
        <div class="stat-card">
            <span class="stat-numero">${totalExemplares}</span>
            <span class="stat-rotulo">Exemplares totais</span>
        </div>
        <div class="stat-card">
            <span class="stat-numero">${emprestimosAtivos}</span>
            <span class="stat-rotulo">Empréstimos ativos</span>
        </div>
        <div class="stat-card ${atrasados > 0 ? 'stat-alerta' : ''}">
            <span class="stat-numero">${atrasados}</span>
            <span class="stat-rotulo">Atrasados</span>
        </div>
    `;
}

// ══════════════════════════════════════
// MODO FUNCIONÁRIO - ACERVO
// ══════════════════════════════════════

function renderizarAcervo() {
    const container = document.getElementById('lista-acervo');

    if (livrosCache.length === 0) {
        container.innerHTML = '<p class="mensagem-info">Nenhum livro cadastrado</p>';
        return;
    }

    let html = '<div class="grid-acervo">';

    livrosCache.forEach(livro => {
        const titulo = escapeHtml(livro.titulo);
        const autor = escapeHtml(livro.autor);
        const imagem = escapeHtml(urlImagemSegura(livro.imagem));

        html += `
            <div class="card-acervo">
                <img src="${imagem}" alt="${titulo}" loading="lazy">
                <h4>${titulo}</h4>
                <p class="autor">${autor}</p>
                <p class="estoque">Estoque: ${Number(livro.estoque) || 0}</p>
                <div class="acoes-card">
                    <button class="secundario" onclick="editarLivro(${livro.id})">Editar</button>
                    <button class="btn-remover" onclick="excluirLivro(${livro.id})">Excluir</button>
                </div>
            </div>
        `;
    });

    html += '</div>';
    container.innerHTML = html;
}

// Cabeçalhos padrão para chamadas autenticadas do modo funcionário
function headersFuncionario() {
    return {
        'Content-Type': 'application/json',
        'x-auth-token': tokenFuncionario || ''
    };
}

// Trata respostas 401 de forma consistente: derruba a sessão local
// e devolve o funcionário para a tela de login.
async function tratarRespostaAutenticada(response) {
    if (response.status === 401) {
        tokenFuncionario = null;
        sessionStorage.removeItem('tokenFuncionario');
        mostrarToast('Sua sessão de funcionário expirou. Faça login novamente.', 'erro');
        alternarModo('funcionario');
        return true;
    }
    return false;
}

async function adicionarLivro(e) {
    e.preventDefault();

    const titulo = document.getElementById('titulo-livro').value.trim();
    const autor = document.getElementById('autor-livro').value.trim();
    const quantidadeStr = document.getElementById('quantidade-livro').value;
    const quantidade = parseInt(quantidadeStr, 10);
    const imagem = document.getElementById('imagem-livro').value.trim();

    if (!titulo || !autor) {
        mostrarToast('Preencha todos os campos obrigatórios', 'erro');
        return;
    }

    if (quantidadeStr === '' || isNaN(quantidade) || quantidade < 0) {
        mostrarToast('Informe uma quantidade válida (número inteiro maior ou igual a zero)', 'erro');
        return;
    }

    try {
        const response = await fetch(`${API_URL}/books`, {
            method: 'POST',
            headers: headersFuncionario(),
            body: JSON.stringify({ titulo, autor, estoque: quantidade, imagem })
        });

        if (await tratarRespostaAutenticada(response)) return;

        if (response.ok) {
            mostrarToast('Livro adicionado com sucesso!', 'sucesso');
            document.getElementById('form-adicionar-livro').reset();
            await carregarAcervo();
            renderizarDashboardFuncionario();
        } else {
            const dados = await response.json();
            mostrarToast(dados.erro || 'Erro ao adicionar livro', 'erro');
        }
    } catch (erro) {
        console.error('Erro ao adicionar livro:', erro);
        mostrarToast('Erro ao adicionar livro', 'erro');
    }
}

async function editarLivro(livroId) {
    const livro = livrosCache.find(l => l.id === livroId);
    if (!livro) return;

    const novoEstoque = prompt('Nova quantidade em estoque:', livro.estoque);
    if (novoEstoque === null) return;

    const quantidade = parseInt(novoEstoque, 10);

    if (isNaN(quantidade) || quantidade < 0) {
        mostrarToast('Quantidade inválida', 'erro');
        return;
    }

    try {
        const response = await fetch(`${API_URL}/books/${livroId}`, {
            method: 'PUT',
            headers: headersFuncionario(),
            body: JSON.stringify({ estoque: quantidade })
        });

        if (await tratarRespostaAutenticada(response)) return;

        if (response.ok) {
            mostrarToast('Livro atualizado com sucesso!', 'sucesso');
            await carregarAcervo();
            renderizarDashboardFuncionario();
        } else {
            const dados = await response.json();
            mostrarToast(dados.erro || 'Erro ao atualizar livro', 'erro');
        }
    } catch (erro) {
        console.error('Erro ao atualizar livro:', erro);
        mostrarToast('Erro ao atualizar livro', 'erro');
    }
}

async function excluirLivro(livroId) {
    if (!confirm('Deseja realmente excluir este livro?')) return;

    try {
        const response = await fetch(`${API_URL}/books/${livroId}`, {
            method: 'DELETE',
            headers: headersFuncionario()
        });

        if (await tratarRespostaAutenticada(response)) return;

        if (response.ok) {
            mostrarToast('Livro excluído com sucesso!', 'sucesso');
            await carregarAcervo();
            renderizarDashboardFuncionario();
        } else {
            const dados = await response.json();
            mostrarToast(dados.erro || 'Erro ao excluir livro', 'erro');
        }
    } catch (erro) {
        console.error('Erro ao excluir livro:', erro);
        mostrarToast('Erro ao excluir livro', 'erro');
    }
}

// ══════════════════════════════════════
// MODO FUNCIONÁRIO - EMPRÉSTIMOS
// ══════════════════════════════════════

function renderizarEmprestimos() {
    const container = document.getElementById('lista-emprestimos');

    // Ativos vêm de /rentals. Já devolvidos NÃO existem mais em /rentals
    // (o servidor os move para /history na devolução) — por isso a lista
    // de "devolvidos" é montada a partir do histórico, não do cache de aluguéis.
    const ativos = alugueisCache.filter(a => !a.devolvido);
    const devolvidos = [...historicoCache]
        .sort((a, b) => new Date(b.dataDevolucao) - new Date(a.dataDevolucao))
        .slice(0, 20);

    let html = '<div class="emprestimos-container">';

    html += '<h4>Empréstimos Ativos</h4>';

    if (ativos.length === 0) {
        html += '<p class="mensagem-info">Nenhum empréstimo ativo</p>';
    } else {
        html += '<div class="lista-emprestimos">';

        ativos.forEach(aluguel => {
            const status = aluguel.status || 'lendo';
            const dataAluguel = new Date(aluguel.dataAluguel).toLocaleDateString('pt-BR');
            const vencimento = calcularVencimento(aluguel);
            const atrasado = estaAtrasado(aluguel);
            const titulo = escapeHtml(aluguel.livroTitulo);
            const autor = escapeHtml(aluguel.livroAutor);

            html += `
                <div class="item-emprestimo ${atrasado ? 'atrasado' : ''}">
                    <div class="info-emprestimo">
                        <h4>${titulo}</h4>
                        <p>Autor: ${autor}</p>
                        <p>Alugado em: ${dataAluguel}</p>
                        <p>Devolver até: ${vencimento.toLocaleDateString('pt-BR')}
                            ${atrasado ? '<span class="badge badge-atrasado">Atrasado</span>' : ''}
                        </p>
                        <p>Status: <span class="badge badge-${status}">${escapeHtml(status)}</span></p>
                    </div>
                    <div class="acoes-emprestimo">
                        <button class="secundario" onclick="registrarDevolucaoFuncionario(${aluguel.id})">Registrar Devolução</button>
                    </div>
                </div>
            `;
        });

        html += '</div>';
    }

    html += '<h4 style="margin-top: 30px;">Empréstimos Devolvidos Recentemente</h4>';

    if (devolvidos.length === 0) {
        html += '<p class="mensagem-info">Nenhum empréstimo devolvido ainda</p>';
    } else {
        html += '<div class="lista-emprestimos">';

        devolvidos.forEach(item => {
            const dataAluguel = new Date(item.dataAluguel).toLocaleDateString('pt-BR');
            const dataDevolucao = item.dataDevolucao ? new Date(item.dataDevolucao).toLocaleDateString('pt-BR') : '-';
            const titulo = escapeHtml(item.livroTitulo);
            const autor = escapeHtml(item.livroAutor);

            html += `
                <div class="item-emprestimo devolvido">
                    <div class="info-emprestimo">
                        <h4>${titulo}</h4>
                        <p>Autor: ${autor}</p>
                        <p>Alugado em: ${dataAluguel}</p>
                        <p>Devolvido em: ${dataDevolucao}</p>
                    </div>
                </div>
            `;
        });

        html += '</div>';
    }

    html += '</div>';
    container.innerHTML = html;
}

async function registrarDevolucaoFuncionario(aluguelId) {
    if (!confirm('Deseja registrar a devolução deste livro?')) return;

    try {
        const response = await fetch(`${API_URL}/rentals/${aluguelId}`, { method: 'DELETE' });

        if (response.ok) {
            mostrarToast('Devolução registrada com sucesso!', 'sucesso');
            await carregarEmprestimos();
            await carregarAcervo();
            await carregarHistorico();
            renderizarDashboardFuncionario();
        } else {
            const dados = await response.json();
            mostrarToast(dados.erro || 'Erro ao registrar devolução', 'erro');
        }
    } catch (erro) {
        console.error('Erro ao registrar devolução:', erro);
        mostrarToast('Erro ao registrar devolução', 'erro');
    }
}
