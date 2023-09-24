#include <stdlib.h> // 표준 라이브러리 함수들을 사용하기 위한 헤더 파일
#include <stdio.h> // 입출력 관련 함수들을 사용하기 위한 헤더 파일
#include <pcap.h> // pcap 라이브러리를 사용하기 위한 헤더 파일
#include <arpa/inet.h> // 인터넷 작업을 위한 함수와 구조체를 제공하는 헤더 파일

/* 이더넷 헤더 */
struct ethheader {
  u_char  ether_dhost[6]; /* 목적지 호스트 주소 */ 
  u_char  ether_shost[6]; /* 출발지 호스트 주소 */
  u_short ether_type;     /* 프로토콜 유형 (IP, ARP, RARP 등) */
}; // 이더넷 헤더를 정의하는 구조체

/* IP 헤더 */
struct ipheader {
  unsigned char      iph_ihl:4, //IP 헤더 길이
                     iph_ver:4; //IP 버전
  unsigned char      iph_tos; //서비스 유형
  unsigned short int iph_len; //IP 패킷 길이 (데이터 + 헤더)
  unsigned short int iph_ident; //식별자
  unsigned short int iph_flag:3, //파편화 플래그
                     iph_offset:13; //플래그 오프셋
  unsigned char      iph_ttl; //시간 제한 (Time to Live)
  unsigned char      iph_protocol; //프로토콜 유형
  unsigned short int iph_chksum; //IP 데이터그램 체크섬
	struct in_addr     iph_sourceip;/* 출발지 IP 주소*/
	struct in_addr     iph_destip;/* 목적지 IP 주소*/
}; //IP 헤더를 정의하는 구조체 

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{ 
    struct ethheader *eth = (struct ethheader *)packet;
    // 패킷 데이터를 이더넷 헤더 구조체로 변환하여 사용
    
    if (ntohs(eth->ether_type) == 0x0800) { 
    // 이 패킷이 IP 프로토콜을 사용하는지 확인
    
        struct ipheader * ip = (struct ipheader *)(packet + sizeof(struct ethheader)); 
        // 패킷 데이터에서 이더넷 헤더 다음 부분을 IP 헤더 구조체로 변환하여 사용
        
        printf("       From: %s", inet_ntoa(ip->iph_sourceip));   
				// 출발지 IP 주소를 문자열로 변환하여 출력

		printf("         To: %s", inet_ntoa(ip->iph_destip));    
				// 목적지 IP 주소를 문자열로 변환하여 출력

switch(ip->iph_protocol) {                                 
    case IPPROTO_TCP:
        printf("   Protocol: TCP\n");
        return;
        // 프로토콜이 TCP인 경우 "Protocol: TCP"를 출력하고 함수 종료
        
    case IPPROTO_UDP:
        printf("   Protocol: UDP\n");
        return;
        // 프로토콜이 UDP인 경우 "Protocol: UDP"를 출력하고 함수 종료
        
    case IPPROTO_ICMP:
        printf("   Protocol: ICMP\n");
        return;
        // 프로토콜이 ICMP인 경우 "Protocol: ICMP"를 출력하고 함수 종료
        
    default:
        printf("   Protocol: others\n");
        return;
       // 위의 경우가 아닌 다른 프로토콜인 경우 "Protocol: others"을 출력하고 함수 종료
}
       }
    }
}
// 패킷 캡처시 호출되는 콜백함수. 패킷 정보 출력 및 프로토콜 결정

int main()
{
  pcap_t *handle; // pcap 세션 핸들러를 위한 포인터
  char errbuf[PCAP_ERRBUF_SIZE]; // 에러 메시지를 저장할 버퍼
  struct bpf_program fp; // 필터 프로그램을 위한 구조체
  char filter_exp[] = "tcp"; // 필터 표현식. TCP 프로토콜만 캡처하도록 설정
  bpf_u_int32 net; // 네트워크 번호

  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
   /* 네트워크 인터페이스에서 실시간으로 패킷을 캡처할 수 있는 pcap 세션 열기 
    * 첫 번째 파라미터는 장치 이름(enp0s3), 두 번째는 최대 바이트 수(BUFSIZ),
    * 세 번째는 promiscuous mode(1은 활성화), 네 번째는 타임아웃 시간(1000ms),
    * 마지막은 에러 메시지를 저장할 버퍼 */

   pcap_compile(handle, &fp, filter_exp, 0, net);
   /* 필터 표현식을 컴파일하여 BPF(bytecode program)로 변환
    * 첫 번째 파라미터는 pcap 핸들러,
    * 두 번째 파라미터는 컴파일된 결과를 저장할 구조체,
    * 세 번째 파라미터가 실제 필터 표현식,
    * 네 번째와 마지막 파라미터는 IPv4 네크워크 숫자와 마스크 */

   if (pcap_setfilter(handle, &fp) !=0) {
       pcap_perror(handle,"Error:");
       exit(EXIT_FAILURE);
   }
   /* BPF 프로그램을 설정함으로써 패킷 캡처 시 해당 필터가 적용되도록 함.
    * 만약 설정에 실패하면 에러 메시지를 출력하고 프로그램 종료 */
}
   // 필터를 설정하여 TCP 프로토콜을 사용하는 패킷만 캡처

   pcap_loop(handle,-1,got_packet,NULL);
   // 지정된 개수(-1은 무한대를 의미)의 패킷을 캡처하고 각각에 대해 got_packet 함수 호출

   pcap_close(handle);   
   // 핸들을 닫고, 리소스 해제
   
   return(0); 
}
// 메인 함수. pcap 세션 열고, 필터 설정 후 패킷 캡처 시작