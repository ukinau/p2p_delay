#include <stdio.h>
#include <regex.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/types.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include <pcap.h>

#include "libGeoIP/GeoIP.h"
#include "libGeoIP/GeoIPCity.h"
#include "libGeoIP/GeoIP_internal.h"

#define MAX_IPADDRESS 300
#define MAX_PROCESS_COUNT 1 
#define MAX_TRACEROUTE_RESULT_STRING 3048
#define MAX_TRACEROUTE_RESULT_HOP 100 //traceroute result 

static int process_count; 
char used_ipaddress_list[MAX_IPADDRESS][16];
static int global_ipaddress_count;
/* geoip extra info used in _say_range_ip */
int info_flag = 0;

struct iphdr {
 unsigned int ihl:4;
 unsigned int version:4;
 unsigned char tos;
 unsigned short tot_len;
 unsigned short id;
 unsigned short frag_off;
 unsigned char ttl;
 unsigned char protocol;
 unsigned short check;
 unsigned int saddr;
 unsigned int daddr;
 };

struct DelayData{
  char ipaddress[16];
  int hop_count;
};

struct SettingOption{
  FILE *log_fp;
  int dummy_mode;
};

int fork_exec(char *ipaddress,FILE *log_fp, int dummy_mode);
void insert_delay(char *ipaddress, FILE *log_fp, int dummy_mode);
void excec_traceroute(char *ipaddress, char *traceroute_result, int dummy_mode);
void calculate_hop_count(char ipaddress_list[][16], struct DelayData *target_data, int dummy_mode);

void output_log(struct DelayData *data, FILE *fp);
void fomat_traceroute_result(char *traceroute_result, char ipaddress_list[][16]);

int management_process( u_char *user, const struct pcap_pkthdr *h, const u_char *p);
int used_ipaddress(char *ipaddress);
void add_ipaddress_list(char *ipaddress);
void check_and_collect_childprocess();

void geoiplookup(GeoIP * gi, char *hostname, int i, char *geo_result);

int main(int argc, char** argv){
  //グローバル変数の初期化
  process_count = 0; //現在の子プロセス数の初期化
  global_ipaddress_count = 0;

  int dummy_mode = 0;// 0:production , 1:dummy
  FILE *log_fp;

  // pcap用の変数
  char *nic;
  pcap_t *pd;
  int snaplen = 64;
  int promiscuous_mode_flg = 1;
  int timeout = 1000;
  char error_buffer[250];
  bpf_u_int32 localnet, netmask;
  pcap_handler callback;
  struct bpf_program fcode;

  if(argc < 2){
    fprintf(stderr, "NICを指定してください");
    exit(1);
  }

  nic = argv[1];

  if((log_fp = fopen("log.txt", "w")) == NULL){
    fprintf(stderr,"logfile open error\n");
    exit(1);
  }

  if((pd = pcap_open_live(nic, snaplen, !promiscuous_mode_flg, timeout, error_buffer)) == NULL){
    fprintf(stderr,"Can't open pcap device\n");
    exit(1);
  }
  // get infromations of network interface 
  if( pcap_lookupnet(nic, &localnet, &netmask, error_buffer) < 0){
    fprintf(stderr, "Can't get interface informartions\n");
    exit(1);
  }


  // compile condition
  if( pcap_compile(pd, &fcode, "ip and tcp or udp or icmp", 1, netmask) < 0 ){
    fprintf(stderr, "can't compile fileter\n");
    exit(1);
  }

  // set filter
  if( pcap_setfilter(pd, &fcode) < 0){
    fprintf(stderr, "can't set filter");
    exit(1);
  }

  callback =(pcap_handler)management_process;

  struct SettingOption setting;
  struct SettingOption *setting_pointer;
  setting.log_fp = log_fp;
  setting.dummy_mode = dummy_mode;
  setting_pointer = &setting;

  if(pcap_loop(pd, 4000, callback, (u_char *)setting_pointer) < 0){
    fprintf(stderr, "pcap_loop: error occurred\n");
    exit(1);
  }

  while(process_count > 0){
    check_and_collect_childprocess();
  }

  pcap_close(pd);
  

  return 0;

}

int management_process( u_char *user, const struct pcap_pkthdr *h, const u_char *p){
  struct SettingOption *setting = (struct SettingOption *)user;
  FILE *log_fp = setting->log_fp;
  int process_count_max = MAX_PROCESS_COUNT; 
  int dummy_mode = setting->dummy_mode;
  char *ipaddress;

  struct ether_header *eh;
  struct iphdr *iph;
  struct in_addr st_saddr;
  char c_saddr[32];

  eh = (struct ether_header *)p;
  if ( htons(eh->ether_type) == ETHERTYPE_IP ) {
    iph = (struct iphdr *)((void *)p + ETHER_HDR_LEN );
    st_saddr.s_addr = iph->saddr;
    strcpy( c_saddr, inet_ntoa( st_saddr ) );
  }

  ipaddress = c_saddr;

  check_and_collect_childprocess();
  if(!used_ipaddress(ipaddress)){
    while(1){
      //子プロセス数が最大値を超えてないか？
      if(process_count < process_count_max){
        int p = fork_exec(ipaddress, log_fp, dummy_mode);
        add_ipaddress_list(ipaddress);
        printf("create & start child[%d][%s]\n",p,ipaddress);
        break;
      }
      else{
        check_and_collect_childprocess();
      }
    }
  }
}

/**
 * 子プロセスが終了しているか、チェックし終了したら回収する
 **/
void check_and_collect_childprocess(){
  int status;
  int p = waitpid(-1, &status, WNOHANG);
  if(p > 0){
    printf("child[%d] end\n",p);
    process_count--;
  }
}

/**
 * 既に実行したIPアドレスかどうか
 **/
int used_ipaddress(char *ipaddress){
  int i = 0;
  for(i = 0;i<global_ipaddress_count;i++){
    if(strcmp(used_ipaddress_list[i],ipaddress) == 0){
      return 1;
    }
  }
  return 0;
}

/**
 * 実行したIPアドレスとしてリストに登録
 **/
void add_ipaddress_list(char *ipaddress){
  global_ipaddress_count++;
  strcpy(used_ipaddress_list[global_ipaddress_count-1],ipaddress);
}

/**
 * 子プロセスを生成して、遅延挿入処理を実行
 **/
int fork_exec(char *ipaddress,FILE *log_fp, int dummy_mode){
  int pid;
  //子プロセスの生成
  if((pid = fork()) == -1){
    // error check
    perror("insert_delay:fork");
    printf("Can't excute fork & traceroute to %s",ipaddress);
  }else{
    switch(pid){
      case 0://child process
        insert_delay(ipaddress,log_fp,dummy_mode);
        _exit(0);
        break;
      default:// parent process
        process_count++;
        break;
    }
  }
  return pid;
}

/**
 * 遅延挿入処理
 **/
void insert_delay(char *ipaddress, FILE *log_fp, int dummy_mode){
  char traceroute_result[MAX_TRACEROUTE_RESULT_STRING];
  char ipaddress_list[MAX_TRACEROUTE_RESULT_HOP][16];
  struct DelayData data; //ipaddressとhop数を格納する構造体
  int i = 0;

  for(i = 0; i<MAX_TRACEROUTE_RESULT_HOP; i++){
    ipaddress_list[i][0] = '\0';
  }

  strcpy(data.ipaddress, ipaddress); 
  excec_traceroute(ipaddress, traceroute_result, dummy_mode);
  //traceresultの結果から、ipaddress_listにip_addressのみを抜き出し
  fomat_traceroute_result(traceroute_result, ipaddress_list);
  //ipaddressからホップ数をカウント
  calculate_hop_count(ipaddress_list, &data, dummy_mode);

  output_log(&data, log_fp);
  if(dummy_mode){ sleep(5); }
}

/**
 * ログの出力
 **/
void output_log(struct DelayData *data, FILE *fp){
  char output_line[100];
  sprintf(output_line, "IP:%s HOP数:%d\n",data->ipaddress,data->hop_count);
  fwrite(output_line,(int)strlen(output_line),1,fp);
  fclose(fp);
}

/**
 * tracerouteを実行して、結果を文字列として保存
 **/
void excec_traceroute(char *ipaddress, char *traceroute_result, int dummy_mode){
  char dummy_result[] = "traceroute to 202.18.114.8 (202.18.114.8), 64 hops max, 72 byte packets\n1  web.setup (192.168.0.1)  3.540 ms\n2  119.107.194.19 (119.107.194.19)  90.059 ms\n3  172.27.73.236 (172.27.73.236)  92.671 ms\n 4  172.30.67.46 (172.30.67.46)  168.896 ms\n5  aa20111001946f573af2.userreverse.dion.ne.jp (111.87.58.242)  103.367 ms\n6  aa20111001946f573a01.userreverse.dion.ne.jp (111.87.58.1)  113.924 ms\n7  111.87.11.61 (111.87.11.61)  103.407 ms\n8  obpjbb205.int-gw.kddi.ne.jp (118.155.199.25)  163.888 ms\n9  otejbb205.int-gw.kddi.ne.jp (59.128.4.101)  199.264 ms\n10  ix-ote206.int-gw.kddi.ne.jp (106.187.6.54)  119.043 ms\n11  as2907.ix.jpix.ad.jp (210.171.224.150)  198.949 ms\n12  tokyo-dc-rm-ae4-vlan10.s4.sinet.ad.jp (150.99.2.53)  134.065 ms\n13  shibaura-it.gw.sinet.ad.jp (150.99.197.106)  179.208 ms\n17  * * *\n18  * * *\n19  * * *\n20  * * *\n26  aa20111001946f573a01.userreverse.dion.ne.jp (111.87.58.1)  99.291 ms\n27  xe-0-1-0-4.r00.tokyjp03.jp.ce.gin.ntt.net (61.213.161.66)  79.157 ms\n28 limelight-gcn.tengigabitethernet6-4.408.ar5.sea1.gblx.net (208.178.63.118)  307.801 ms\n29  cr2-pos0-0-0-0.sanfrancisco.savvis.net (204.70.192.90)  224.756 ms  224.241 ms  210.776 ms\n30  cr1-te-0-5-0-3.lay.savvis.net (206.28.97.245)  210.151 ms  164.700 ms  203.870 ms\n31  63-235-40-86.dia.static.qwest.net (63.235.40.86)  205.284 ms  204.215 ms  210.274 ms\n32  63-235-40-86.dia.static.qwest.net (63.235.40.86)  214.030 ms\n33  cr2-te-0-5-0-3.lay.savvis.net (206.28.97.249)  209.728 ms\n34  cr2-tengig0-7-0-0.sanfrancisco.savvis.net (204.70.196.198)  328.361 ms";
  char command_str[50];
  if(dummy_mode){
    strcpy(traceroute_result, dummy_result);
  }else{
    sprintf(command_str,"traceroute -q 1 -w 1 -P icmp %s \n",ipaddress);
    system_get_value(command_str,traceroute_result);
  }
}

/**
 * HOP数を数える
 **/
void calculate_hop_count(char ipaddress_list[][16], struct DelayData *target_data, int dummy_mode){
  char geo_ip_result[256]; 
  char custom_file[] = "geodata/GeoIPASNum.dat";
  int charset = GEOIP_CHARSET_UTF8;
  int edition;
  int i=0;
  int j=0;
  int regitered_flg = 0;
  int hop_count = 0;
  char *ipadrress;
  char geo_ip_results[40][256]; //geo_results;
  GeoIP *gi;

  for(i=0; i<40; i++){
    geo_ip_results[i][0] = '\0';
  }

  if(dummy_mode){
    target_data->hop_count = 6; 
  }else{

    char result_file_path[100];
    sprintf(result_file_path, "result/%s",target_data->ipaddress);
    FILE *test_fp = fopen(result_file_path,"w");
    char output_line[200];
    
  
    _GeoIP_setup_dbfilename();
    gi = GeoIP_open(custom_file, GEOIP_STANDARD);
    gi->charset = charset;
    edition = GeoIP_database_edition(gi);

    i=0;
    while( ipaddress_list[i][0] != '\0' ){
      regitered_flg = 0;
      j=0;
      geoiplookup(gi, ipaddress_list[i], edition, geo_ip_result);

      sprintf(output_line, "IP:%s ISP:%s\n",ipaddress_list[i], geo_ip_result);
      fwrite(output_line,(int)strlen(output_line),1,test_fp);

      //既に登録した、ISPか調べる
      while( geo_ip_results[j][0] != '\0' ){
        if(strcmp(geo_ip_results[j], geo_ip_result) == 0){
          regitered_flg = 1; 
        }
        j++;
      }
      if(!regitered_flg){
        hop_count++;
        strcpy(geo_ip_results[hop_count-1], geo_ip_result);
      }
      i++;
    }
    fclose(test_fp);
    GeoIP_delete(gi);
    target_data->hop_count = hop_count; 
     
  }
}


/**
 * ipadrressのみの文字列にする
 **/
void fomat_traceroute_result(char *traceroute_result, char ipaddress_list[][16]){
  regex_t preg;
  size_t nmatch = 1;
  regmatch_t pmatch[nmatch];
  char *tmp;
  int i=0;

  //正規表現パターンのコンパイル
  if(regcomp(&preg, "((2[0-4][0-9]|25[0-5]|[01]?[0-9][0-9]|[0-9])\\.(2[0-4][0-9]|25[0-5]|[01]?[0-9][0-9]|[0-9])\\.(2[0-4][0-9]|25[0-5]|[01]?[0-9][0-9]|[0-9])\\.(2[0-4][0-9]|25[0-5]|[01]?[0-9][0-9]|[0-9]))", REG_EXTENDED|REG_NEWLINE) != 0){
    printf("Regex compile failed \n");
  }

  //一行目の切り捨て
  //printf("before-str:%s\n",traceroute_result);
  tmp = strtok(traceroute_result,"\n");
  i = 0;
  while( tmp != NULL ){
    //一行ずつ読み出し
    tmp = strtok(NULL, "\n"); 
    if( tmp != NULL ){
      //正規表現マッチ
      if(regexec(&preg, tmp, nmatch, pmatch, 0) != 0){
         printf("no match\n");
         strcpy(ipaddress_list[i],"icmp_timeout");
      }  
      else{
        //正規表現マッチの結果（ip-addressを出力)
        if(pmatch[0].rm_so >= 0 && pmatch[0].rm_eo >= 0){
           strncpy(ipaddress_list[i], tmp+pmatch[0].rm_so, pmatch[0].rm_eo-pmatch[0].rm_so);
           ipaddress_list[i][pmatch[0].rm_eo-pmatch[0].rm_so] = '\0';
        }
      }
    }
    i++;
  }

}

/**
 * コマンドを実行して、その出力を変数に格納する
 **/
int system_get_value(const char *cmd, char *target_str){
  FILE *process_fp;
  char tmp[200];
  process_fp = popen(cmd, "r");
  
  strcpy(target_str,cmd);
  while(fgets(tmp,200,process_fp) != NULL){
    strcat(target_str,tmp);
  }
  pclose(process_fp);
  return 1;
}


/*geo ip */

static const char * _mk_NA( const char * p )
{
    return p ? p : "N/A";
}

static unsigned long
__addr_to_num(const char *addr)
{
    unsigned int c, octet, t;
    unsigned long ipnum;
    int i = 3;

    octet = ipnum = 0;
    while ((c = *addr++)) {
        if (c == '.') {
            if (octet > 255) {
                return 0;
            }
            ipnum <<= 8;
            ipnum += octet;
            i--;
            octet = 0;
        } else {
            t = octet;
            octet <<= 3;
            octet += t;
            octet += t;
            c -= '0';
            if (c > 9) {
                return 0;
            }
            octet += c;
        }
    }
    if ((octet > 255) || (i != 0)) {
        return 0;
    }
    ipnum <<= 8;
    return ipnum + octet;
}



/* ptr must be a memory area with at least 16 bytes */
static char *__num_to_addr_r(unsigned long ipnum, char * ptr)
{
    char *cur_str;
    int octet[4];
    int num_chars_written, i;

    cur_str = ptr;

    for (i = 0; i < 4; i++) {
        octet[3 - i] = ipnum % 256;
        ipnum >>= 8;
    }

    for (i = 0; i < 4; i++) {
        num_chars_written = sprintf(cur_str, "%d", octet[i]);
        cur_str += num_chars_written;

        if (i < 3) {
            cur_str[0] = '.';
            cur_str++;
        }
    }

    return ptr;
}

void _say_range_by_ip(GeoIP * gi, uint32_t ipnum )
{
    unsigned long last_nm, mask, low, hi;
    char ipaddr[16];
    char tmp[16];
    char ** range;

    if (info_flag == 0) {
        return; /* noop unless extra information is requested */

    }
    range = GeoIP_range_by_ip( gi, __num_to_addr_r( ipnum, ipaddr ) );
    if (range == NULL) {
        return;
    }

    printf( "  ipaddr: %s\n", ipaddr );

    printf( "  range_by_ip:  %s - %s\n", range[0], range[1] );
    last_nm = GeoIP_last_netmask(gi);
    mask = 0xffffffff << ( 32 - last_nm );
    low = ipnum & mask;
    hi = low + ( 0xffffffff & ~mask );
    printf( "  network:      %s - %s ::%ld\n",
            __num_to_addr_r( low, ipaddr ),
            __num_to_addr_r( hi, tmp ),
            last_nm
            );
    printf( "  ipnum: %u\n", ipnum );
    printf( "  range_by_num: %lu - %lu\n", __addr_to_num(
                range[0]), __addr_to_num(range[1]) );
    printf( "  network num:  %lu - %lu ::%lu\n", low, hi, last_nm );

    GeoIP_range_by_ip_delete(range);
}

void
geoiplookup(GeoIP * gi, char *hostname, int i, char *geo_result)
{
    const char *country_code;
    const char *country_name;
    const char *domain_name;
    const char *asnum_name;
    int netspeed;
    int country_id;
    GeoIPRegion *region;
    GeoIPRecord *gir;
    const char *org;
    uint32_t ipnum;

    ipnum = _GeoIP_lookupaddress(hostname);
    if (ipnum == 0) {
        printf("%s: can't resolve hostname ( %s )\n", GeoIPDBDescription[i],
               hostname);

    }else {

        if (GEOIP_DOMAIN_EDITION == i) {
            domain_name = GeoIP_name_by_ipnum(gi, ipnum);
            if (domain_name == NULL) {
                printf("%s: IP Address not found\n", GeoIPDBDescription[i]);
            }else {
                printf("%s: %s\n", GeoIPDBDescription[i], domain_name);
                _say_range_by_ip(gi, ipnum);
            }
        }else if (GEOIP_LOCATIONA_EDITION == i ||
                  GEOIP_ACCURACYRADIUS_EDITION == i
                  || GEOIP_ASNUM_EDITION == i || GEOIP_USERTYPE_EDITION == i
                  || GEOIP_REGISTRAR_EDITION == i ||
                  GEOIP_NETSPEED_EDITION_REV1 == i
                  || GEOIP_COUNTRYCONF_EDITION == i ||
                  GEOIP_CITYCONF_EDITION == i
                  || GEOIP_REGIONCONF_EDITION == i ||
                  GEOIP_POSTALCONF_EDITION == i) {
            asnum_name = GeoIP_name_by_ipnum(gi, ipnum);
            if (asnum_name == NULL) {
                strcpy(geo_result, "TODO_IP_ADDRESS_NOT_FOUND");
            }else {
            //    printf("%s: %s\n", GeoIPDBDescription[i], asnum_name);
                strcpy(geo_result, asnum_name);
                _say_range_by_ip(gi, ipnum);
            }
        }else if (GEOIP_COUNTRY_EDITION == i) {
            country_id = GeoIP_id_by_ipnum(gi, ipnum);
            country_code = GeoIP_country_code[country_id];
            country_name = GeoIP_country_name[country_id];
            if (country_id == 0) {
                printf("%s: IP Address not found\n", GeoIPDBDescription[i]);
            }else {
                printf("%s: %s, %s\n", GeoIPDBDescription[i], country_code,
                       country_name);
                _say_range_by_ip(gi, ipnum);
            }
        }else if (GEOIP_REGION_EDITION_REV0 == i ||
                  GEOIP_REGION_EDITION_REV1 == i) {
            region = GeoIP_region_by_ipnum(gi, ipnum);
            if (NULL == region || region->country_code[0] == '\0') {
                printf("%s: IP Address not found\n", GeoIPDBDescription[i]);
            }else {
                printf("%s: %s, %s\n", GeoIPDBDescription[i],
                       region->country_code,
                       region->region);
                _say_range_by_ip(gi, ipnum);
            }
            if (region) {
                GeoIPRegion_delete(region);
            }
        }else if (GEOIP_CITY_EDITION_REV0 == i) {
            gir = GeoIP_record_by_ipnum(gi, ipnum);
            if (NULL == gir) {
                printf("%s: IP Address not found\n", GeoIPDBDescription[i]);
            }else {
                printf("%s: %s, %s, %s, %s, %s, %f, %f\n",
                       GeoIPDBDescription[i], gir->country_code, _mk_NA(
                           gir->region),
                       _mk_NA(GeoIP_region_name_by_code(gir->country_code,
                                                        gir->region)),
                       _mk_NA(gir->city), _mk_NA(
                           gir->postal_code), gir->latitude, gir->longitude);
                _say_range_by_ip(gi, ipnum);
                GeoIPRecord_delete(gir);
            }
        }else if (GEOIP_CITY_EDITION_REV1 == i) {
            gir = GeoIP_record_by_ipnum(gi, ipnum);
            if (NULL == gir) {
                printf("%s: IP Address not found\n", GeoIPDBDescription[i]);
            }else {
                printf("%s: %s, %s, %s, %s, %s, %f, %f, %d, %d\n",
                       GeoIPDBDescription[i], gir->country_code, _mk_NA(
                           gir->region),
                       _mk_NA(GeoIP_region_name_by_code(gir->country_code,
                                                        gir->region)),
                       _mk_NA(gir->city), _mk_NA(
                           gir->postal_code),
                       gir->latitude, gir->longitude, gir->metro_code,
                       gir->area_code);
                _say_range_by_ip(gi, ipnum);
                GeoIPRecord_delete(gir);
            }
        }else if (GEOIP_ORG_EDITION == i || GEOIP_ISP_EDITION == i) {
            org = GeoIP_org_by_ipnum(gi, ipnum);
            if (org == NULL) {
                printf("%s: IP Address not found\n", GeoIPDBDescription[i]);
            }else {
                printf("%s: %s\n", GeoIPDBDescription[i], org);
                _say_range_by_ip(gi, ipnum);
            }
        }else if (GEOIP_NETSPEED_EDITION == i) {
            netspeed = GeoIP_id_by_ipnum(gi, ipnum);
            if (netspeed == GEOIP_UNKNOWN_SPEED) {
                printf("%s: Unknown\n", GeoIPDBDescription[i]);
            }else if (netspeed == GEOIP_DIALUP_SPEED) {
                printf("%s: Dialup\n", GeoIPDBDescription[i]);
            }else if (netspeed == GEOIP_CABLEDSL_SPEED) {
                printf("%s: Cable/DSL\n", GeoIPDBDescription[i]);
            }else if (netspeed == GEOIP_CORPORATE_SPEED) {
                printf("%s: Corporate\n", GeoIPDBDescription[i]);
            }
            _say_range_by_ip(gi, ipnum);
        }else {

            /*
             * Silent ignore IPv6 databases. Otherwise we get annoying
             * messages whenever we have a mixed environment IPv4 and
             *  IPv6
             */

            /*
             * printf("Can not handle database type -- try geoiplookup6\n");
             */
            ;
        }
    }
}
