// group ipv4/ipv6 list from stdout into subnets
// each line must contain either ip or ip/bitcount
// valid ip/bitcount and ip1-ip2 are passed through without modification
// ips are groupped into subnets

// can be compiled in mingw. msvc not supported because of absent getopt

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#ifdef _WIN32
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x600
#include <winsock2.h>
#include <ws2ipdef.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif
#include <getopt.h>
#include "qsort.h"

#define ALLOC_STEP 16384

struct ip_range
{
	uint32_t ip1,ip2;
};
struct ip_range6
{
	struct in6_addr ip1,ip2;
};


static int ucmp(const void * a, const void * b, void *arg)
{
	if (*(uint32_t*)a < *(uint32_t*)b)
		return -1;
	else if (*(uint32_t*)a > *(uint32_t*)b)
		return 1;
	else
		return 0;
}
static uint32_t mask_from_bitcount(uint32_t zct)
{
	return zct<32 ? ~((1 << zct) - 1) : 0;
}
// make presorted array unique. return number of unique items.
// 1,1,2,3,3,0,0,0 (ct=8) => 1,2,3,0 (ct=4)
static uint32_t unique(uint32_t *pu, uint32_t ct)
{
	uint32_t i, j, u;
	for (i = j = 0; j < ct; i++)
	{
		u = pu[j++];
		for (; j < ct && pu[j] == u; j++);
		pu[i] = u;
	}
	return i;
}



#if defined(__GNUC__) && !defined(__llvm__)
__attribute__((optimize ("no-strict-aliasing")))
#endif
static int cmp6(const void * a, const void * b, void *arg)
{
	// this function is critical for sort performance
	// on big endian systems cpu byte order is equal to network byte order
	// no conversion required. it's possible to improve speed by using big size compares
	// on little endian systems byte conversion also gives better result than byte comparision
	// 64-bit archs often have cpu command to reverse byte order
	// assume that a and b are properly aligned

#if defined(__BYTE_ORDER__) && ((__BYTE_ORDER__==__ORDER_BIG_ENDIAN__) || (__BYTE_ORDER__==__ORDER_LITTLE_ENDIAN__))

	uint64_t aa,bb;
#if __BYTE_ORDER__==__ORDER_LITTLE_ENDIAN__
	aa = __builtin_bswap64(((uint64_t*)((struct in6_addr *)a)->s6_addr)[0]);
	bb = __builtin_bswap64(((uint64_t*)((struct in6_addr *)b)->s6_addr)[0]);
#else
	aa = ((uint64_t*)((struct in6_addr *)a)->s6_addr)[0];
	bb = ((uint64_t*)((struct in6_addr *)b)->s6_addr)[0];
#endif
	if (aa < bb)
		return -1;
	else if (aa > bb)
		return 1;
	else
	{
#if __BYTE_ORDER__==__ORDER_LITTLE_ENDIAN__
		aa = __builtin_bswap64(((uint64_t*)((struct in6_addr *)a)->s6_addr)[1]);
		bb = __builtin_bswap64(((uint64_t*)((struct in6_addr *)b)->s6_addr)[1]);
#else
		aa = ((uint64_t*)((struct in6_addr *)a)->s6_addr)[1];
		bb = ((uint64_t*)((struct in6_addr *)b)->s6_addr)[1];
#endif
		return aa < bb ? -1 : aa > bb ? 1 : 0;
	}
	
#else
	// fallback case
	for (uint8_t i = 0; i < sizeof(((struct in6_addr *)0)->s6_addr); i++)
	{
		if (((struct in6_addr *)a)->s6_addr[i] < ((struct in6_addr *)b)->s6_addr[i])
			return -1;
		else if (((struct in6_addr *)a)->s6_addr[i] > ((struct in6_addr *)b)->s6_addr[i])
			return 1;
	}
	return 0;
#endif
}
#if defined(__GNUC__) && !defined(__llvm__)
__attribute__((optimize ("no-strict-aliasing")))
#endif
static int cmp6_ipr(const void * a, const void * b, void *arg)
{
	int r;
	r=cmp6(&((struct ip_range6*)a)->ip1,&((struct ip_range6*)b)->ip1,arg);
	return r ? r : cmp6(&((struct ip_range6*)a)->ip2,&((struct ip_range6*)b)->ip2,arg);
}
#if defined(__GNUC__) && !defined(__llvm__)
__attribute__((optimize ("no-strict-aliasing")))
#endif
static int cmp_ipr(const void * a, const void * b, void *arg)
{
	int r;
	r=ucmp(&((struct ip_range*)a)->ip1,&((struct ip_range*)b)->ip1,arg);
	return r ? r : ucmp(&((struct ip_range*)a)->ip2,&((struct ip_range*)b)->ip2,arg);
}

// make presorted array unique. return number of unique items.
static uint32_t unique6(struct in6_addr *pu, uint32_t ct)
{
	uint32_t i, j, k;
	for (i = j = 0; j < ct; i++)
	{
		for (k = j++; j < ct && !memcmp(pu + j, pu + k, sizeof(struct in6_addr)); j++);
		pu[i] = pu[k];
	}
	return i;
}
static void mask_from_bitcount6_make(uint32_t zct, struct in6_addr *a)
{
	if (zct >= 128)
		memset(a->s6_addr,0x00,16);
	else
	{
		int32_t n = (127 - zct) >> 3;
		memset(a->s6_addr,0xFF,n);
		memset(a->s6_addr+n,0x00,16-n);
		a->s6_addr[n] = ~((1 << (zct & 7)) - 1);
	}
}
static struct in6_addr ip6_mask[129],ip6_inv_mask[129];
#if defined(__GNUC__) && !defined(__llvm__)
__attribute__((optimize ("no-strict-aliasing")))
#endif
static void mask_from_bitcount6_prepare()
{
	for (int zct=0;zct<=128;zct++)
	{
		mask_from_bitcount6_make(zct, ip6_mask+zct);
#ifdef __SIZEOF_INT128__
		*((unsigned __int128*)ip6_inv_mask[zct].s6_addr) = ~*((unsigned __int128*)ip6_mask[zct].s6_addr);
#else
		((uint64_t*)ip6_inv_mask[zct].s6_addr)[0] = ~((uint64_t*)ip6_mask[zct].s6_addr)[0];
		((uint64_t*)ip6_inv_mask[zct].s6_addr)[1] = ~((uint64_t*)ip6_mask[zct].s6_addr)[1];
#endif

	}
}
static inline const struct in6_addr *mask_from_bitcount6(uint32_t zct)
{
	return ip6_mask+zct;
}
static inline const struct in6_addr *inv_mask_from_bitcount6(uint32_t zct)
{
	return ip6_inv_mask+zct;
}


#if defined(__GNUC__) && !defined(__llvm__)
__attribute__((optimize ("no-strict-aliasing")))
#endif
static void ip6_and(const struct in6_addr *a, const struct in6_addr *b, struct in6_addr *result)
{
#ifdef __SIZEOF_INT128__
	// gcc and clang have 128 bit int types on some 64-bit archs. take some advantage
	*((unsigned __int128*)result->s6_addr) = *((unsigned __int128*)a->s6_addr) & *((unsigned __int128*)b->s6_addr);
#else
	((uint64_t*)result->s6_addr)[0] = ((uint64_t*)a->s6_addr)[0] & ((uint64_t*)b->s6_addr)[0];
	((uint64_t*)result->s6_addr)[1] = ((uint64_t*)a->s6_addr)[1] & ((uint64_t*)b->s6_addr)[1];
#endif
}
#if defined(__GNUC__) && !defined(__llvm__)
__attribute__((optimize ("no-strict-aliasing")))
#endif
static void ip6_or(const struct in6_addr *a, const struct in6_addr *b, struct in6_addr *result)
{
#ifdef __SIZEOF_INT128__
	// gcc and clang have 128 bit int types on some 64-bit archs. take some advantage
	*((unsigned __int128*)result->s6_addr) = *((unsigned __int128*)a->s6_addr) | *((unsigned __int128*)b->s6_addr);
#else
	((uint64_t*)result->s6_addr)[0] = ((uint64_t*)a->s6_addr)[0] | ((uint64_t*)b->s6_addr)[0];
	((uint64_t*)result->s6_addr)[1] = ((uint64_t*)a->s6_addr)[1] | ((uint64_t*)b->s6_addr)[1];
#endif
}

static void rtrim(char *s)
{
	if (s)
		for (char *p = s + strlen(s) - 1; p >= s && (*p == '\n' || *p == '\r'); p--) *p = '\0';
}

static void print_ip_range6(const struct ip_range6* ipr)
{
	char s1[40],s2[40];
	if (inet_ntop(AF_INET6,&ipr->ip1,s1,sizeof(s1)) && inet_ntop(AF_INET6,&ipr->ip2,s2,sizeof(s2)))
		printf("%s-%s\n",s1,s2);
}
static void print_ip6(const struct in6_addr* ip6)
{
	char s1[40];
	if (inet_ntop(AF_INET6,ip6,s1,sizeof(s1)))
		printf("%s\n",s1);
}
static void print_ip_range(const struct ip_range* ipr)
{
	printf("%u.%u.%u.%u-%u.%u.%u.%u\n",ipr->ip1>>24, (ipr->ip1>>16)&0xFF, (ipr->ip1>>8)&0xFF, ipr->ip1&0xFF, ipr->ip2>>24, (ipr->ip2>>16)&0xFF, (ipr->ip2>>8)&0xFF, ipr->ip2&0xFF);
}
static void print_ip(uint32_t a)
{
	printf("%u.%u.%u.%u\n",a>>24, (a>>16)&0xFF, (a>>8)&0xFF, a&0xFF);
}



typedef	enum {undef=0,exclude,intersect} t_filter_mode;

static struct params_s
{
	bool ipv6;
	char filter_filename[256];
	t_filter_mode mode;
} params;


static void exithelp()
{
	printf("\n"
		" -4\t\t\t\t; ipv4 list (default)\n"
		" -6\t\t\t\t; ipv6 list\n"
		" --mode\t\t\t\t; intersect or exclude\n"
		" --filter\t\t\t; filter subnet list file\n"
		"\n"
		"input must be ip address list read from stdin. may not include subnets.\n"
		"filter may contain ip addresses, ranges ip1-ip2 and ip/prefixlen\n"
		"output goes to stdout\n"
	);
	exit(1);
}

static void parse_params(int argc, char *argv[])
{
	int option_index = 0;
	int v, i;
	uint32_t plen1=-1, plen2=-1;

	memset(&params, 0, sizeof(params));

	const struct option long_options[] = {
		{ "help",no_argument,0,0 },// optidx=0
		{ "h",no_argument,0,0 },// optidx=1
		{ "4",no_argument,0,0 },// optidx=2
		{ "6",no_argument,0,0 },// optidx=3
		{ "mode",required_argument,0,0 },// optidx=4
		{ "filter",required_argument,0,0 },// optidx=5
		{ NULL,0,NULL,0 }
	};
	while ((v = getopt_long_only(argc, argv, "", long_options, &option_index)) != -1)
	{
		if (v) exithelp();
		switch (option_index)
		{
		case 0:
		case 1:
			exithelp();
			break;
		case 2:
			params.ipv6 = false;
			break;
		case 3:
			params.ipv6 = true;
			break;
		case 4:
			if (!strcmp(optarg,"exclude"))
				params.mode = exclude;
			else if (!strcmp(optarg,"intersect"))
				params.mode = intersect;
			else
			{
				fprintf(stderr,"bad value for mode : %s\n",optarg);
				exit(2);
			}
			break;
		case 5:
			strncpy(params.filter_filename, optarg, sizeof(params.filter_filename));
			params.filter_filename[sizeof(params.filter_filename) - 1] = '\0';
			break;
		}
	}
	if (params.mode==undef)
	{
		fprintf(stderr, "mode must be specified\n");
		exit(1);
	}
}

#define MAX(a,b) (a)>(b) ? (a) : (b)

static bool list_belong6(const struct ip_range6 *iplist, uint32_t ipct, const struct in6_addr *a)
{
	uint32_t pos,pos_start,pos_end;

	pos=ipct/2; pos_start=0; pos_end = ipct;

	// binary search
	while(pos<pos_end)
	{
		if (cmp6(a,&iplist[pos].ip1,NULL)<0) // a is lower than ip1 at pos
		{
			pos_end = pos;
			pos = pos/2;
		} else
		{
			if (cmp6(a,&iplist[pos].ip2,NULL)<=0) // a is lower or equal than ip2 at pos
				return true; // hit
			else
			{
				pos_start = pos+1;
				pos += MAX(1,(pos_end-pos)/2);
			}
		}
	}
	
	return false;
}
static bool list_check6(t_filter_mode mode,const struct ip_range6 *iplist, uint32_t ipct, const struct in6_addr *a)
{
	bool b;

	if (mode!=exclude && mode!=intersect) return false;
	b = list_belong6(iplist,ipct,a);
	//printf("belong %u\n",b);
	return mode==exclude && !b || mode==intersect && b;
}

static bool list_belong(const struct ip_range *iplist, uint32_t ipct, uint32_t a)
{
	uint32_t pos,pos_start,pos_end;

	pos=ipct/2; pos_start=0; pos_end = ipct;

	// binary search
	while(pos<pos_end)
	{
		if (a < iplist[pos].ip1) // a is lower than ip1 at pos
		{
			pos_end = pos;
			pos = pos/2;
		} else
		{
			if (a<=iplist[pos].ip2) // a is lower or equal than ip2 at pos
				return true; // hit
			else
			{
				pos_start = pos+1;
				pos += MAX(1,(pos_end-pos)/2);
			}
		}
	}
	
	return false;
}
static bool list_check(t_filter_mode mode,const struct ip_range *iplist, uint32_t ipct, uint32_t a)
{
	bool b;

	if (mode!=exclude && mode!=intersect) return false;
	b = list_belong(iplist,ipct,a);
	//printf("belong %u\n",b);
	return mode==exclude && !b || mode==intersect && b;
}


static int Run()
{
	char str[256],str2[256], *s, d;
	uint32_t ipct = 0, iplist_size = 0, zct, ip_ct;
	FILE *F;
	bool ok;

	F = fopen(params.filter_filename,"rt");
	if (!F)
	{
		fprintf(stderr,"cannot open %s\n",params.filter_filename);
		return 10;
	}

	if (params.ipv6)
	{
		struct in6_addr a;
		struct ip_range6 ar, *iplist = NULL, *iplist_new;

		mask_from_bitcount6_prepare();

		while (fgets(str, sizeof(str), F))
		{
			ok = false;
			rtrim(str);
			strcpy(str2,str);
			d = 0;
			if ((s = strchr(str, '/')) || (s = strchr(str, '-')))
			{
				d = *s;
				*s = '\0';
			}
			if (inet_pton(AF_INET6, str, &ar.ip1))
			{
				if (d=='/')
				{
					// we have subnet ip6/y
					// output it as is
					if (sscanf(s + 1, "%u", &zct)==1)
					{
						if (zct<128)
						{
							zct = 128-zct;
							ip6_and(&ar.ip1,mask_from_bitcount6(zct),&ar.ip1);
							ip6_or(&ar.ip1,inv_mask_from_bitcount6(zct),&ar.ip2);
							ok = true;
						}
						else if (zct==128)
						{
							ar.ip2 = ar.ip1;
							ok = true;
						}
					}
				}
				else if (d=='-')
				{
					if (inet_pton(AF_INET6, s+1, &ar.ip2) && cmp6(&ar.ip2,&ar.ip1,NULL)>=0) ok=1;
				}
				else
				{
					ar.ip2 = ar.ip1;
					ok = true;
				}
			}
			if (ok)
			{
				if (ipct >= iplist_size)
				{
					iplist_size += ALLOC_STEP;
					iplist_new = (struct ip_range6*)(iplist ? realloc(iplist, sizeof(*iplist)*iplist_size) : malloc(sizeof(*iplist)*iplist_size));
					if (!iplist_new)
					{
						free(iplist);
						fprintf(stderr, "out of memory\n");
						fclose(F);
						return 100;
					}
					iplist = iplist_new;
				}
				iplist[ipct++] = ar;
			}
			else
				fprintf(stderr,"bad filter entry : %s\n",str2);
		}
		fclose(F);
		fflush(stderr);

		gnu_quicksort(iplist, ipct, sizeof(*iplist), cmp6_ipr, NULL);
		//for(uint32_t i=0;i<ipct;i++) print_ip_range6(iplist+i);
		fflush(stdout);

		while (fgets(str, sizeof(str), stdin))
		{
			rtrim(str);
			if (s = strchr(str, '/'))
			{
				*s = 0;
				if (sscanf(s + 1, "%u", &zct)!=1 || zct!=128)
				{
					fprintf(stderr,"bad ip6 prefix. only /128 is supported. : %s/%s\n",str,s+1);
					continue;
				}
			}
			if (inet_pton(AF_INET6, str, &a))
			{
				if (list_check6(params.mode,iplist,ipct,&a))
					print_ip6(&a);
			}
			else
			{
				fprintf(stderr,"bad ip6 : %s\n",str);
			}
		}

		free(iplist);
	}
	else // ipv4
	{
		int i;
		uint32_t a, u1,u2,u3,u4, u11,u22,u33,u44, mask;
		struct ip_range ar, *iplist = NULL, *iplist_new;

		while (fgets(str, sizeof(str), F))
		{
			ok = false;
			rtrim(str);

			zct=32;
			if ((i = sscanf(str, "%u.%u.%u.%u-%u.%u.%u.%u", &u1, &u2, &u3, &u4, &u11, &u22, &u33, &u44)) >= 8 && 
				!(u1 & 0xFFFFFF00) && !(u2 & 0xFFFFFF00) && !(u3 & 0xFFFFFF00) && !(u4 & 0xFFFFFF00) &&
				!(u11 & 0xFFFFFF00) && !(u22 & 0xFFFFFF00) && !(u33 & 0xFFFFFF00) && !(u44 & 0xFFFFFF00))
			{
				ar.ip1 = u1 << 24 | u2 << 16 | u3 << 8 | u4;
				ar.ip2 = u11 << 24 | u22 << 16 | u33 << 8 | u44;
				ok = true;
			}
			else if ((i = sscanf(str, "%u.%u.%u.%u/%u", &u1, &u2, &u3, &u4, &zct)) >= 4 &&
				!(u1 & 0xFFFFFF00) && !(u2 & 0xFFFFFF00) && !(u3 & 0xFFFFFF00) && !(u4 & 0xFFFFFF00) && zct<=32)
			{
				mask = mask_from_bitcount(32-zct);
				ar.ip1 = (u1 << 24 | u2 << 16 | u3 << 8 | u4) & mask;
				ar.ip2 = ar.ip1 | ~mask;
				ok = true;
			}

			if (ok)
			{
				if (ipct >= iplist_size)
				{
					iplist_size += ALLOC_STEP;
					iplist_new = (struct ip_range*)(iplist ? realloc(iplist, sizeof(*iplist)*iplist_size) : malloc(sizeof(*iplist)*iplist_size));
					if (!iplist_new)
					{
						free(iplist);
						fprintf(stderr, "out of memory\n");
						fclose(F);
						return 100;
					}
					iplist = iplist_new;
				}
				iplist[ipct++] = ar;
			}
			else
				fprintf(stderr,"bad filter entry : %s\n",str);
		}
		fclose(F);
		fflush(stderr);

		gnu_quicksort(iplist, ipct, sizeof(*iplist), cmp_ipr, NULL);
		//for(uint32_t i=0;i<ipct;i++) print_ip_range(iplist+i);
		fflush(stdout);

		while (fgets(str, sizeof(str), stdin))
		{
			rtrim(str);
			zct = 32;
			if ((i = sscanf(str, "%u.%u.%u.%u/%u", &u1, &u2, &u3, &u4, &zct)) >= 4 &&
				!(u1 & 0xFFFFFF00) && !(u2 & 0xFFFFFF00) && !(u3 & 0xFFFFFF00) && !(u4 & 0xFFFFFF00) && zct==32)
			{
				a = ar.ip2 = u1 << 24 | u2 << 16 | u3 << 8 | u4;
				if (list_check(params.mode,iplist,ipct,a))
					print_ip(a);
			}
			else
			{
				fprintf(stderr,"bad ip addr or prefix. only /32 is supported. : %s\n",str);
			}
		}

		free(iplist);
	}

	return 0;
}

int main(int argc, char **argv)
{
	parse_params(argc, argv);
	return Run();
}
