📋 Documentação Técnica — Windows Reverse TCP Shell

Índice

Visão Geral

Arquitetura do Shellcode

Análise Detalhada

Melhorias Implementadas

Considerações de Uso (Conceitual)

Defesas e Detecção

Referências

Disclaimer

Notas de Versão

🎯 Visão Geral
Propósito

Este projeto documenta a análise técnica de um shellcode para Windows (x86/x64) que estabelece uma comunicação TCP reversa e redireciona a entrada e saída de um processo remoto.

O objetivo é estudo, engenharia reversa, avaliação de comportamento e desenvolvimento de mecanismos de defesa.

Características Principais

Tamanho: ~330 bytes (versão compacta)

Arquitetura: x86 (32-bit)

Plataforma: Windows XP / 7 / 8 / 10 / 11

Protocolo: TCP/IP

Método: Resolução dinâmica de APIs

## 🔄 Diagrama de Fluxo (Alto Nível)

```text
┌───────────────┐
│     Início    │
└───────┬───────┘
        │
        ▼
┌─────────────────┐
│ PEB Walking      │ ← Localiza módulos carregados
└───────┬─────────┘
        │
        ▼
┌─────────────────┐
│ Export Table     │ ← Localiza funções exportadas
│ Parsing           │
└───────┬─────────┘
        │
        ▼
┌─────────────────┐
│ LoadLibraryA     │ ← Carrega dependências
└───────┬─────────┘
        │
        ▼
┌─────────────────┐
│ WSAStartup       │ ← Inicializa Winsock
└───────┬─────────┘
        │
        ▼
┌─────────────────┐
│ WSASocketA       │ ← Criação de socket TCP
└───────┬─────────┘
        │
        ▼
┌─────────────────┐
│ connect()        │ ← Estabelece conexão
└───────┬─────────┘
        │
        ▼
┌──────────────────────────┐
│ CreateProcessA           │ ← I/O redirecionado
└───────┬──────────────────┘
        │
        ▼
┌─────────────────┐
│ Shell Interativo │
└─────────────────┘

🏗️ Arquitetura do Shellcode
Fase 1 — PEB Walking (Process Environment Block)

Objetivo
Localizar dinamicamente bibliotecas carregadas no processo sem depender da Import Address Table.

Fluxo lógico

Acessa o TEB via segmento FS.

Obtém o ponteiro para o PEB.

Navega na estrutura PEB_LDR_DATA.

Itera sobre a lista de módulos em memória.

Identifica a base de uma biblioteca fundamental do sistema.

Estruturas relevantes

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;   // +0x0C
} PEB, *PPEB;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList; // +0x14
} PEB_LDR_DATA, *PPEB_LDR_DATA;

Observação
Esse padrão é amplamente conhecido e monitorado por soluções EDR.

Fase 2 — Export Table Parsing

Objetivo
Resolver dinamicamente endereços de funções diretamente na estrutura PE do módulo.

Conceitos envolvidos

DOS Header

PE Header (e_lfanew)

Optional Header

Export Directory

AddressOfNames

AddressOfOrdinals

AddressOfFunctions

DOS Header
   ↓
PE Header
   ↓
Optional Header
   ↓
Export Directory

Essa abordagem elimina dependência de símbolos estáticos.

Fase 3 — Resolução de GetProcAddress

Objetivo

Localizar dinamicamente a função responsável por resolver endereços de outras APIs.

Por que isso é relevante

Permite encadeamento dinâmico de chamadas.

Evita hardcoding de endereços.

Mitiga impactos do ASLR.

Risco operacional

O padrão de busca por export table é facilmente detectável em análise comportamental.

Fase 4 — Carregamento de APIs

APIs normalmente envolvidas

LoadLibraryA

Inicialização de rede

Criação de socket

Estabelecimento de conexão

Criação de processo

Técnica observada

Construção dinâmica de strings em memória.

Uso de chamadas indiretas.

Fase 5 — Inicialização de Rede

Objetivo

Inicializar a pilha de rede.

Preparar estruturas internas.

Criar um socket para comunicação.

Indicadores comportamentais

Alocação dinâmica de memória.

Inicialização explícita de bibliotecas de rede.

Criação de handles de socket.

Fase 6 — Criação de Socket

Parâmetros típicos

AF_INET: IPv4

SOCK_STREAM: TCP

IPPROTO_TCP: Protocolo TCP

Essa etapa gera eventos facilmente rastreáveis por telemetria de host.

Fase 7 — Conexão

Objetivo

Estabelecer uma sessão TCP com um endpoint remoto definido em tempo de build ou runtime.

Endereços e portas são tratados como parâmetros abstratos nesta documentação.

Fase 8 — Criação de Processo com I/O Redirecionado

Objetivo

Associar stdin, stdout e stderr a um canal de comunicação.

Permitir troca remota de dados.

Estrutura relevante

typedef struct _STARTUPINFOA {
    DWORD cb;
    LPSTR lpReserved;
    LPSTR lpDesktop;
    LPSTR lpTitle;
    DWORD dwX, dwY;
    DWORD dwXSize, dwYSize;
    DWORD dwXCountChars, dwYCountChars;
    DWORD dwFillAttribute;
    DWORD dwFlags;
    WORD  wShowWindow;
    WORD  cbReserved2;
    LPBYTE lpReserved2;
    HANDLE hStdInput;
    HANDLE hStdOutput;
    HANDLE hStdError;
} STARTUPINFOA;

🔍 Análise Detalhada
Técnicas de Evasão
✔️ Resolução Dinâmica de APIs

Vantagens

Não aparece na IAT.

Reduz artefatos estáticos.

Compatibilidade entre versões.

Desvantagens

Overhead de execução.

Padrões comportamentais bem conhecidos.

Alta visibilidade em EDR moderno.

✔️ Construção de Strings em Runtime

Motivação

Evitar strings visíveis em análise estática.

Reduz assinaturas triviais.

Limitação

Não impede detecção comportamental.

✔️ Payload Compacto

Benefícios

Menor footprint em memória.

Facilidade de transporte.

Limitações

Baixa flexibilidade.

Pouca capacidade de resiliência.

Limitações Técnicas

Ausência de criptografia.

Dependência de parâmetros estáticos.

Sem persistência.

Sem autenticação de sessão.

Esses fatores tornam o comportamento facilmente detectável.

⚡ Melhorias Implementadas
Arquitetura em C++

Encapsulamento.

Gerenciamento de recursos.

Facilidade de extensão.

Validação de Ambiente

Verificação de integridade.

Avaliação de proteções do sistema.

Compatibilidade de plataforma.

Tratamento de Erros

Controle estruturado de exceções.

Registro de falhas.

Logging

Rastreamento de estados internos.

Diagnóstico de falhas.

Auditoria de execução.

Configuração Dinâmica

Parametrização de variáveis operacionais.

Patch controlado em memória.

📖 Considerações de Uso (Conceitual)

Esta documentação descreve comportamento e arquitetura, não procedimentos operacionais.

Qualquer execução deve ocorrer exclusivamente em:

Ambientes de laboratório controlados.

Testes autorizados.

Pesquisa acadêmica.

Simulações defensivas.

🛡️ Defesas e Detecção
Detecção em Rede

Monitoramento de conexões de saída incomuns.

Inspeção de padrões de tráfego.

Correlação de sessões persistentes.

Detecção em Host

Monitoramento de alocação de memória executável.

Análise de chamadas indiretas.

Detecção de redirecionamento de I/O.

Cadeias anômalas de criação de processos.

Mitigações

DEP

ASLR

CFG

Firewall de aplicação

Princípio do menor privilégio

📚 Referências

Documentação

Microsoft PE Format

Winsock API

Process Environment Block

Literatura

Windows Internals

Practical Malware Analysis

The Shellcoder’s Handbook

⚖️ Disclaimer

Este material é destinado exclusivamente para:

Educação em cibersegurança

Pesquisa técnica

Testes autorizados

Desenvolvimento defensivo

É proibido o uso fora de ambientes legalmente autorizados.

📝 Notas de Versão

Versão 2.0 (2026)

Refatoração em C++

Validação de ambiente

Logging

Configuração dinâmica

Documentação ampliada

Shellcode original

Implementação básica
