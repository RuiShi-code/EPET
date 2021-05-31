#ifndef EPET_H
#define EPET_H

#include"pairing_3.h"
#include "zzn.h"
#include <stdlib.h>
#include <stdio.h>
typedef unsigned char u8;
typedef unsigned int u32;
#define AES_SECURITY 128
#define ATTRIBUTES_NUM 10
#define DISCLOSE_NUM 3
//pp and ca
struct URS_PRI_KEY_CA
{
    Big x;
    Big y[ATTRIBUTES_NUM];
};
struct URS_PUB_KEY_CA
{
    G2 X_;
    G1 Y[ATTRIBUTES_NUM];
    G2 Y_[ATTRIBUTES_NUM];
    G2 Z_[ATTRIBUTES_NUM][ATTRIBUTES_NUM];
};
struct SPS_PRI_KEY_CA
{
    Big d;
    Big e[4];
};
struct SPS_PUB_KEY_CA
{
    G2 h_;
    G1 D;
    G1 E[4];

};
struct PP
{
    URS_PUB_KEY_CA urs_pub;
    SPS_PUB_KEY_CA sps_pub;
};

struct MSK
{
    URS_PRI_KEY_CA urs_pri;
    SPS_PRI_KEY_CA sps_pri;
};
//user key
struct USER_KEY
{
    Big usk;
    G1  upk;
};
//seller key
struct SELLER_PRI_KEY
{
    Big x;
    Big y[4];

};
struct SELLER_PUB_KEY
{
    G2 X_;
    G1 Y[4];
    G2 Y_[4];
    G2 Z02_,Z12_,Z32_;

};
struct SELLER_KEY
{
    SELLER_PRI_KEY pri_key;
    SELLER_PUB_KEY pub_key;
};
//POK1
struct POK1
{
    Big c1;
    Big s1;
};
//Cred_u
struct CRED_U
{
    G1 sigma1;
    G1 sigma2;
};

//POK1
struct POK2
{
    Big c2;
    Big t[5];
};
//Cred_s
struct CRED_S
{
    G1 A;
    G2 B_,C_;
};
//Tick
struct TICK_PRI
{
   Big dsid,dsrnd;
};
struct TICKET
{
    G1 T1,T2;
    Big dsid_s,VP_t;
};
//POK3
struct POK3
{
    GT D;
    Big c3;
    Big su,sd,sr;
};
//User derive URS
struct DERIVE_CRED
{
   G1 sigma1,sigma2;
   G2 sigma1_,sigma2_;
   GT sigma3;
   Big s;
};
struct USER_ATTR
{
    Big Attr[ATTRIBUTES_NUM];
};
struct DISCLOSE_ATTR
{
    int index[DISCLOSE_NUM];
    Big attr[DISCLOSE_NUM];
};
//Obtain Process user info
struct USER_PURCH_INFO
{
    DERIVE_CRED derive;
    G1 Psu;
    POK3 pok3;
    DISCLOSE_ATTR diclose;
};
struct POK4
{
    Big c4;
    Big st,sr;

};
struct DERIVE_TICK
{
    G1 T1,T2;
    G2 T1_,T2_;
    GT T3;
    Big s;

};
struct USER_SHOW_INFO
{
    Big dsid,VP_t;
    POK4 pok4;
    DERIVE_TICK derive;

};
struct BLAME_INFO
{
    Big dstag;
    Big s,c;
};
class EPET
{
private:
    PFC *pfc;
    G1 g;
    G2 g_;

public:
    EPET(PFC *p);
    ~EPET();
    //KeyGen
    int SetUp(PP &pp,MSK &msk);//128 or 192
    int UserKG(USER_KEY &user_key);
    int SellerKG(SELLER_KEY &seller_key);

    //ObtainCred_u-----IssueCred_u process
    int GenerateAttributes(USER_ATTR &attr);//The first is the usk (init 0), the last is the VT_u(init 0), and the others are replaced by random numbers
    int ObtainCred_u_Send(USER_KEY &user_key,POK1 &pok1);
    int IssueCred_u(G1 &upk, USER_ATTR &attr, POK1 &pok1, MSK &msk, Big &VP_u, CRED_U &cred_u);
    int ObtainCred_u_Receive(PP &pp, CRED_U &cred_u, Big &usk, USER_ATTR &attr, Big &VP_u);

    //obtain Creds----IssueCreds process
    int ObtainCred_s_Send(SELLER_KEY &seller_key,POK2 &pok2);
    int IssueCred_s(SELLER_PUB_KEY &seller_pub,POK2 &pok2,PP &pp, MSK &msk,CRED_S &cred_s);
    int ObtainCred_s_Receive(SELLER_PUB_KEY &seller_pub, CRED_S &cred_s, PP &pp);
    int VerifySellerCred_s(SELLER_PUB_KEY &seller_pub, CRED_S &cred_s, PP &pp);

    //ObtainTicket---IssueTicket process
    int ObtainTick_Send(PP &pp,SELLER_PUB_KEY &sell_pub,USER_KEY &user_key,CRED_U &cred_u, USER_ATTR &attr,Big &VP_u,TICK_PRI &tick_pri,USER_PURCH_INFO &purch_info);
    int IssueTick(PP &pp,USER_PURCH_INFO &purch_info,SELLER_KEY &seller_key,TICKET &tick);
    int ObtainTick_Receive(SELLER_PUB_KEY &sell_pub,USER_KEY &user_key,TICK_PRI &tick_pri,TICKET &tick);

    //ShowTickets----ValidTickets process
    int ShowTick(SELLER_PUB_KEY &sell_pub,TICK_PRI &tick_pri,TICKET &tick, USER_KEY &user_key,USER_SHOW_INFO &show_info);
    int ValidTick(SELLER_PUB_KEY &sell_pub, USER_SHOW_INFO &show_info,BLAME_INFO &blame_info);

    //Trace Double-spending
    int TraceDS(BLAME_INFO &blame_info1, BLAME_INFO &blame_info2, USER_KEY &user_key);
    int VerifyDS(USER_KEY &user_key);//return 1 succ, 0 fail

};
#endif // EPET_H
