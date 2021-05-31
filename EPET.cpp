#include"EPET.h"
EPET::EPET(PFC *p)
{
    //generate type3 pairing parameters
    //pfc=new PFC(aes_security);
    //pfc->PFC(aes_security,NULL);
    pfc=p;
    pfc->random(g);
    pfc->random(g_);
}

EPET::~EPET()
{

}
int EPET::SetUp( PP &pp, MSK &msk)
{
    int ret=0;

    //URS keyGen
    pfc->random(msk.urs_pri.x);
    pp.urs_pub.X_=pfc->mult(g_,msk.urs_pri.x);

    for(int i=0;i<ATTRIBUTES_NUM;i++)
    {
        pfc->random(msk.urs_pri.y[i]);
        pp.urs_pub.Y_[i]=pfc->mult(g_,msk.urs_pri.y[i]);
        pp.urs_pub.Y[i]=pfc->mult(g,msk.urs_pri.y[i]);
    }
    for(int i=0;i<ATTRIBUTES_NUM;i++)
    {
        for(int j=0;j<ATTRIBUTES_NUM;j++)
        {
            pp.urs_pub.Z_[i][j]=pfc->mult(g_,msk.urs_pri.y[i]);
            pp.urs_pub.Z_[i][j]=pfc->mult(pp.urs_pub.Z_[i][j],msk.urs_pri.y[j]);
        }
    }

    //SPS keyGen
    pfc->random(msk.sps_pri.d);
    pp.sps_pub.D=pfc->mult(g,msk.sps_pri.d);
    for(int i=0;i<4;i++)
    {
        pfc->random(msk.sps_pri.e[i]);
        pp.sps_pub.E[i]=pfc->mult(g,msk.sps_pri.e[i]);
    }
    pfc->random(pp.sps_pub.h_);
    return ret;
}
int EPET::UserKG(USER_KEY &user_key)
{
    int ret=0;
    pfc->random(user_key.usk);
    user_key.upk=pfc->mult(g,user_key.usk);
    return ret;
}
int EPET::SellerKG(SELLER_KEY &seller_key)
{
    int ret=0;
    pfc->random(seller_key.pri_key.x);
    seller_key.pub_key.X_=pfc->mult(g_,seller_key.pri_key.x);

    for(int i=0;i<4;i++)
    {
        pfc->random(seller_key.pri_key.y[i]);
        seller_key.pub_key.Y[i]=pfc->mult(g,seller_key.pri_key.y[i]);
        seller_key.pub_key.Y_[i]=pfc->mult(g_,seller_key.pri_key.y[i]);
    }

    seller_key.pub_key.Z02_=seller_key.pub_key.Y_[2];
    seller_key.pub_key.Z12_=seller_key.pub_key.Y_[2];
    seller_key.pub_key.Z32_=seller_key.pub_key.Y_[2];

    seller_key.pub_key.Z02_=pfc->mult(seller_key.pub_key.Z02_,seller_key.pri_key.y[0]);
    seller_key.pub_key.Z12_=pfc->mult(seller_key.pub_key.Z12_,seller_key.pri_key.y[1]);
    seller_key.pub_key.Z32_=pfc->mult(seller_key.pub_key.Z32_,seller_key.pri_key.y[3]);

    return ret;

}
int EPET::GenerateAttributes(USER_ATTR &attr)
{
    int ret=0;
    for(int i=1;i<ATTRIBUTES_NUM-1;i++)
        pfc->random(attr.Attr[i]);
    return ret;
}
int EPET::ObtainCred_u_Send(USER_KEY &user_key, POK1 &pok1)
{
    int ret=0;
    Big alfa,t;
    G1 R1;
    //compute pok1
    pfc->random(alfa);
    R1=pfc->mult(g,alfa);
    pfc->start_hash();
    pfc->add_to_hash(user_key.upk);
    pfc->add_to_hash(R1);
    pok1.c1=pfc->finish_hash_to_group();
    t= pfc->Zpmulti(user_key.usk,pok1.c1);
    pok1.s1=pfc->Zpsub(alfa,t);
    return ret;
}
int EPET::IssueCred_u(G1 &upk, USER_ATTR &attr, POK1 &pok1, MSK &msk, Big &VP_u, CRED_U &cred_u)
{
    int ret=0;
    G1 A1,A2,A3;
    //CA verify pok1
    A1=pfc->mult(g,pok1.s1);
    A2=pfc->mult(upk,pok1.c1);
    A3=A1+A2;
    pfc->start_hash();
    pfc->add_to_hash(upk);
    pfc->add_to_hash(A3);
    Big c=pfc->finish_hash_to_group();
    if(c != pok1.c1) return 1;
    // CA compute urs signature
    Big ru;
    pfc->random(ru);
    pfc->random(VP_u);//valid period replaced by random
    cred_u.sigma1=pfc->mult(g,ru);
    Big a1,sum=msk.urs_pri.x;
    a1=pfc->Zpmulti(ru,msk.urs_pri.y[0]);
    A1=pfc->mult(upk,a1);//upk^(ru*yc0)
    for(int i=1;i<ATTRIBUTES_NUM-1;i++)
    {
        a1=pfc->Zpmulti(attr.Attr[i],msk.urs_pri.y[i]);
        sum=pfc->Zpadd(sum,a1);
    }
    a1=pfc->Zpmulti(VP_u,msk.urs_pri.y[ATTRIBUTES_NUM-1]);
    sum=pfc->Zpadd(a1,sum);
    A2=pfc->mult(cred_u.sigma1,sum);
    cred_u.sigma2=A1+A2;
    return ret;
}
int EPET::ObtainCred_u_Receive(PP &pp, CRED_U &cred_u, Big &usk, USER_ATTR &attr, Big &VP_u)
{
    int ret=0;
    G2 A1,SUM=pp.urs_pub.X_;
    A1=pfc->mult(pp.urs_pub.Y_[0],usk);
    SUM=SUM+A1;
    A1=pfc->mult(pp.urs_pub.Y_[ATTRIBUTES_NUM-1],VP_u);
    SUM=SUM+A1;
    for(int i=1;i<ATTRIBUTES_NUM-1;i++)
    {
        A1=pfc->mult(pp.urs_pub.Y_[i],attr.Attr[i]);
        SUM=SUM+A1;
    }
    GT E1,E2;
    E1=pfc->pairing(g_,cred_u.sigma2);
    E2=pfc->pairing(SUM,cred_u.sigma1);
    if(E1!=E2)  return 1;
    else return 0;

}

int EPET::ObtainCred_s_Send(SELLER_KEY &seller_key,POK2 &pok2)
{
    int ret=0;
    //compute pok2
    Big beta[5];
    G2 P_[5];
    for(int i=0;i<5;i++)
    {
        pfc->random(beta[i]);
        P_[i]=pfc->mult(g_,beta[i]);
    }
    pfc->start_hash();
    pfc->add_to_hash(seller_key.pub_key.X_);
    for(int i=0;i<4;i++)
    {
        pfc->add_to_hash(seller_key.pub_key.Y_[i]);
    }
    for(int i=0;i<5;i++)
    {
        pfc->add_to_hash(P_[i]);
    }
    pok2.c2=pfc->finish_hash_to_group();
    Big a;
    a=pfc->Zpmulti(seller_key.pri_key.x,pok2.c2);
    pok2.t[0]=pfc->Zpsub(beta[0],a);
    for(int i=1;i<5;i++)
    {
        a=pfc->Zpmulti(seller_key.pri_key.y[i-1],pok2.c2);
        pok2.t[i]=pfc->Zpsub(beta[i],a);
    }
    return ret;
}

int EPET::IssueCred_s(SELLER_PUB_KEY &seller_pub,POK2 &pok2,PP &pp, MSK &msk, CRED_S &cred_s)
{
    int ret=0;
    G2 A1,A2,R[5];
    //verify pok2
    A1=pfc->mult(g_,pok2.t[0]);
    A2=pfc->mult(seller_pub.X_,pok2.c2);
    R[0]=A1+A2;
    for(int i=1;i<5;i++)
    {
        A1=pfc->mult(g_,pok2.t[i]);
        A2=pfc->mult(seller_pub.Y_[i-1],pok2.c2);
        R[i]=A1+A2;
    }
    pfc->start_hash();
    pfc->add_to_hash(seller_pub.X_);
    for(int i=0;i<4;i++)
    {
        pfc->add_to_hash(seller_pub.Y_[i]);
    }
    for(int i=0;i<5;i++)
    {
        pfc->add_to_hash(R[i]);
    }
    Big c=pfc->finish_hash_to_group();
    if(c != pok2.c2) return 1;
    //computer sps signature
    Big rs;
    pfc->random(rs);
    cred_s.A=pfc->mult(g,pfc->Zpinverse(rs));
    A1=pfc->mult(g_,msk.sps_pri.d);
    A2=A1+pp.sps_pub.h_;
    cred_s.B_=pfc->mult(A2,rs);
    A1=pfc->mult(pp.sps_pub.h_,msk.sps_pri.d);
    cred_s.C_=A1+seller_pub.X_;
    for(int i=0;i<4;i++)
    {
        A1=pfc->mult(seller_pub.Y_[i],msk.sps_pri.e[i]);
        cred_s.C_=cred_s.C_+A1;
    }
    cred_s.C_=pfc->mult(cred_s.C_,rs);
    return ret;
}
int EPET::ObtainCred_s_Receive(SELLER_PUB_KEY &seller_pub,CRED_S &cred_s,PP &pp)
{
    int ret=0;
    GT A1,A2,A3,MUL;
    A1=pfc->pairing(cred_s.C_,cred_s.A);
    A2=pfc->pairing(pp.sps_pub.h_,pp.sps_pub.D);
    A3=pfc->pairing(seller_pub.X_,g);
    MUL=A2*A3;
    for(int i=0;i<4;i++)
    {
        A2=pfc->pairing(seller_pub.Y_[i],pp.sps_pub.E[i]);
        MUL=MUL*A2;
    }
    if(MUL != A1) return 1;
    A1=pfc->pairing(cred_s.B_,cred_s.A);
    A2=pfc->pairing(pp.sps_pub.h_,g);
    A3=pfc->pairing(g_,pp.sps_pub.D);
    MUL=A2*A3;
    if(MUL != A1) return 2;
    return ret;
}
int EPET::VerifySellerCred_s(SELLER_PUB_KEY &seller_pub,CRED_S &cred_s,PP &pp)
{
    if(ObtainCred_s_Receive( seller_pub, cred_s, pp)) return 1;
    GT A1,A2;
    for(int i=0;i<4;i++)
    {
        A1=pfc->pairing(g_,seller_pub.Y[i]);
        A2=pfc->pairing(seller_pub.Y_[i],g);
        if(A1 != A2) return 2;
    }
    A1=pfc->pairing(seller_pub.Y_[0],seller_pub.Y[2]);
    A2=pfc->pairing(seller_pub.Z02_,g);
    if(A1 != A2) return 3;

    A1=pfc->pairing(seller_pub.Y_[1],seller_pub.Y[2]);
    A2=pfc->pairing(seller_pub.Z12_,g);
    if(A1 != A2) return 4;

    A1=pfc->pairing(seller_pub.Y_[3],seller_pub.Y[2]);
    A2=pfc->pairing(seller_pub.Z32_,g);
    if(A1 != A2) return 5;

    return 0;
}

int EPET::ObtainTick_Send(PP &pp, SELLER_PUB_KEY &sell_pub, USER_KEY &user_key, CRED_U &cred_u, USER_ATTR &attr, Big &VP_u, TICK_PRI &tick_pri, USER_PURCH_INFO &purch_info)
{
    Big k,r,t;
    //URS derive
    attr.Attr[0]=user_key.usk;
    attr.Attr[ATTRIBUTES_NUM-1]=VP_u;
    pfc->random(k);
    pfc->random(r);
    pfc->random(t);
    G2 SUM,A1;
    purch_info.derive.sigma1_=pfc->mult(g_,t);
    for(int i=1;i<ATTRIBUTES_NUM-DISCLOSE_NUM;i++)
    {
        A1=pfc->mult(pp.urs_pub.Y_[i],attr.Attr[i]);
        purch_info.derive.sigma1_=purch_info.derive.sigma1_+A1;
    }
    purch_info.derive.sigma2_=pp.urs_pub.Y_[0];
    for(int i=0;i<DISCLOSE_NUM;i++)
    {
        purch_info.diclose.index[i]=ATTRIBUTES_NUM-DISCLOSE_NUM+i;
        purch_info.diclose.attr[i]=attr.Attr[ATTRIBUTES_NUM-DISCLOSE_NUM+i];
        purch_info.derive.sigma2_=purch_info.derive.sigma2_+pp.urs_pub.Y_[ATTRIBUTES_NUM-DISCLOSE_NUM+i];
    }
    purch_info.derive.sigma2_=pfc->mult(purch_info.derive.sigma2_,t);
    for(int j=1;j<ATTRIBUTES_NUM-DISCLOSE_NUM;j++)
    {
        A1=pfc->mult(pp.urs_pub.Z_[0][j],attr.Attr[j]);
        purch_info.derive.sigma2_=purch_info.derive.sigma2_+A1;

    }
    for(int i=ATTRIBUTES_NUM-DISCLOSE_NUM;i<ATTRIBUTES_NUM;i++)
    {
        for(int j=1;j<ATTRIBUTES_NUM-DISCLOSE_NUM;j++)
        {
            A1=pfc->mult(pp.urs_pub.Z_[i][j],attr.Attr[j]);
            purch_info.derive.sigma2_=purch_info.derive.sigma2_+A1;

        }
    }
    purch_info.derive.sigma1=pfc->mult(cred_u.sigma1,r);
    G1 B1;
    B1=pfc->mult(cred_u.sigma2,r);
    purch_info.derive.sigma2=pfc->mult(purch_info.derive.sigma1,t);
    purch_info.derive.sigma2=purch_info.derive.sigma2+B1;

    B1=pfc->mult(purch_info.derive.sigma1,k);
    purch_info.derive.sigma3=pfc->pairing(pp.urs_pub.Y_[0],B1);

    pfc->start_hash();
    pfc->add_to_hash(purch_info.derive.sigma1_);
    pfc->add_to_hash(purch_info.derive.sigma2_);
    pfc->add_to_hash(purch_info.derive.sigma1);
    pfc->add_to_hash(purch_info.derive.sigma2);
    pfc->add_to_hash(purch_info.derive.sigma3);
    Big c=pfc->finish_hash_to_group();
    Big temp=pfc->Zpmulti(c,user_key.usk);
    purch_info.derive.s=pfc->Zpadd(k,temp);
        //PSu
    B1=pfc->mult(purch_info.derive.sigma1,user_key.usk);
    GT D=pfc->pairing(pp.urs_pub.Y_[0],B1);
    pfc->random(tick_pri.dsid);
    pfc->random(tick_pri.dsrnd);
    purch_info.Psu=pfc->mult(sell_pub.Y[0],user_key.usk);
    B1=pfc->mult(sell_pub.Y[1],tick_pri.dsid);
    purch_info.Psu=purch_info.Psu+B1;
    B1=pfc->mult(sell_pub.Y[2],tick_pri.dsrnd);
    purch_info.Psu=purch_info.Psu+B1;

    //pok3
    Big alfau,alfad,alfar;
    pfc->random(alfau);
    pfc->random(alfad);
    pfc->random(alfar);
    GT RD;
    G1 RPsu;
    B1=pfc->mult(purch_info.derive.sigma1,alfau);
    RD=pfc->pairing(pp.urs_pub.Y_[0],B1);

    RPsu=pfc->mult(sell_pub.Y[0],alfau);
    B1=pfc->mult(sell_pub.Y[1],alfad);
    RPsu=RPsu+B1;
    B1=pfc->mult(sell_pub.Y[2],alfar);
    RPsu=RPsu+B1;

    pfc->start_hash();
    pfc->add_to_hash(D);
    pfc->add_to_hash(purch_info.Psu);
    pfc->add_to_hash(RD);
    pfc->add_to_hash(RPsu);
    purch_info.pok3.c3=pfc->finish_hash_to_group();
    temp=pfc->Zpmulti(user_key.usk,purch_info.pok3.c3);
    purch_info.pok3.su=pfc->Zpsub(alfau,temp);
    temp=pfc->Zpmulti(tick_pri.dsid,purch_info.pok3.c3);
    purch_info.pok3.sd=pfc->Zpsub(alfad,temp);
    temp=pfc->Zpmulti(tick_pri.dsrnd,purch_info.pok3.c3);
    purch_info.pok3.sr=pfc->Zpsub(alfar,temp);
    purch_info.pok3.D=D;
    return 0;
}
int EPET::IssueTick(PP &pp,USER_PURCH_INFO &purch_info,SELLER_KEY &seller_key,TICKET &tick)
{
    //verify urs signatue
    G1 A1;
    GT E1,E2,E3;
    pfc->start_hash();
    pfc->add_to_hash(purch_info.derive.sigma1_);
    pfc->add_to_hash(purch_info.derive.sigma2_);
    pfc->add_to_hash(purch_info.derive.sigma1);
    pfc->add_to_hash(purch_info.derive.sigma2);
    pfc->add_to_hash(purch_info.derive.sigma3);
    Big c=pfc->finish_hash_to_group();

    A1=pfc->mult(purch_info.derive.sigma1,purch_info.derive.s);
    E1=pfc->pairing(pp.urs_pub.Y_[0],A1);

    E2=pfc->pairing(g_,purch_info.derive.sigma2);
    E2=pfc->power(E2,c);
    E2=E2*purch_info.derive.sigma3;

    G2 B1,SUM;
    SUM=pp.urs_pub.X_+purch_info.derive.sigma1_;
    for(int i=0;i<DISCLOSE_NUM;i++)
    {
        B1=pfc->mult(pp.urs_pub.Y_[purch_info.diclose.index[i]],purch_info.diclose.attr[i]);
        SUM=SUM+B1;
    }
    E3=pfc->pairing(SUM,purch_info.derive.sigma1);
    E3=pfc->power(E3,c);
    E1=E1*E3;
    if(E1 != E2) return 1;

    A1=pp.urs_pub.Y[0];
    for(int i=0;i<DISCLOSE_NUM;i++)
    {
        A1=A1+pp.urs_pub.Y[purch_info.diclose.index[i]];
    }
    E1=pfc->pairing(purch_info.derive.sigma1_,A1);
    E2=pfc->pairing(purch_info.derive.sigma2_,g);
    if(E1 != E2) return 2;

    //verify pok3
    A1=pfc->mult(purch_info.derive.sigma1,purch_info.pok3.su);
    E1=pfc->pairing(pp.urs_pub.Y_[0],A1);
    E2=pfc->power(purch_info.pok3.D,purch_info.pok3.c3);

    GT RD=E1*E2;

    G1 RPsu=pfc->mult(seller_key.pub_key.Y[0],purch_info.pok3.su);
    A1=pfc->mult(seller_key.pub_key.Y[1],purch_info.pok3.sd);
    RPsu=RPsu+A1;
    A1=pfc->mult(seller_key.pub_key.Y[2],purch_info.pok3.sr);
    RPsu=RPsu+A1;
    A1=pfc->mult(purch_info.Psu,purch_info.pok3.c3);
    RPsu=RPsu+A1;

    pfc->start_hash();
    pfc->add_to_hash(purch_info.pok3.D);
    pfc->add_to_hash(purch_info.Psu);
    pfc->add_to_hash(RD);
    pfc->add_to_hash(RPsu);
    Big c3=pfc->finish_hash_to_group();
    if(c3 != purch_info.pok3.c3) return 3;

    //issue ticket
    Big z;
    pfc->random(tick.dsid_s);
    pfc->random(z);
    pfc->random(tick.VP_t);
    tick.T1=pfc->mult(g,z);
    tick.T2=pfc->mult(purch_info.Psu,z);
    Big t1,t2;
    t1=pfc->Zpmulti(seller_key.pri_key.y[1],tick.dsid_s);
    t2=pfc->Zpmulti(seller_key.pri_key.y[3],tick.VP_t);
    Big temp=pfc->Zpadd(t1,t2);
    t1=pfc->Zpadd(temp,seller_key.pri_key.x);
    temp=pfc->Zpmulti(t1,z);
    A1=pfc->mult(g,temp);
    tick.T2=tick.T2+A1;
    return 0;
}
int EPET::ObtainTick_Receive(SELLER_PUB_KEY &sell_pub, USER_KEY &user_key, TICK_PRI &tick_pri, TICKET &tick)
{
    tick_pri.dsid=pfc->Zpadd(tick_pri.dsid,tick.dsid_s);
    GT E1,E2;
    E1=pfc->pairing(g_,tick.T2);
    G2 A1,SUM;
    SUM=sell_pub.X_;
    A1=pfc->mult(sell_pub.Y_[0],user_key.usk);
    SUM=SUM+A1;
    A1= pfc->mult(sell_pub.Y_[1],tick_pri.dsid);
    SUM=SUM+A1;
    A1=pfc->mult(sell_pub.Y_[2],tick_pri.dsrnd);
    SUM=SUM+A1;
    A1=pfc->mult(sell_pub.Y_[3],tick.VP_t);
    SUM=SUM+A1;
    E2=pfc->pairing(SUM,tick.T1);
    if(E1 !=E2) return 1;

    return 0;
}
//ShowTickets----ValidTickets process
int EPET::ShowTick(SELLER_PUB_KEY &sell_pub, TICK_PRI &tick_pri, TICKET &tick, USER_KEY &user_key, USER_SHOW_INFO &show_info)
{
    //derive urs signature
    Big r,t;
    pfc->random(r);
    pfc->random(t);
    G2 B1,B2;
    show_info.derive.T1_=pfc->mult(g_,t);
    B1=pfc->mult(sell_pub.Y_[2],tick_pri.dsrnd);
    show_info.derive.T1_=show_info.derive.T1_+B1;

    G1 A1,A2;
    B1=sell_pub.Y_[0]+sell_pub.Y_[1]+sell_pub.Y_[3];
    show_info.derive.T2_=pfc->mult(B1,t);
    B1=sell_pub.Z02_+sell_pub.Z12_+sell_pub.Z32_;
    B2=pfc->mult(B1,tick_pri.dsrnd);
    show_info.derive.T2_=show_info.derive.T2_+B2;
    show_info.derive.T1=pfc->mult(tick.T1,r);
    A1=pfc->mult(show_info.derive.T1,t);
    A2=pfc->mult(tick.T2,r);
    show_info.derive.T2=A1+A2;

    A1=pfc->mult(show_info.derive.T1,tick_pri.dsrnd);
    show_info.derive.T3=pfc->pairing(sell_pub.Y_[0],A1);
    pfc->start_hash();
    pfc->add_to_hash(show_info.derive.T1_);
    pfc->add_to_hash(show_info.derive.T2_);
    pfc->add_to_hash(show_info.derive.T1);
    pfc->add_to_hash(show_info.derive.T2);
    pfc->add_to_hash(show_info.derive.T3);
    Big c=pfc->finish_hash_to_group();

    Big temp;
    temp=pfc->Zpmulti(c,user_key.usk);
    show_info.derive.s=pfc->Zpadd(temp,tick_pri.dsrnd);


    //compute pok4
    Big alfar,alfat;
    pfc->random(alfar);
    pfc->random(alfat);
    G2 R1;
    GT R2;
    R1=pfc->mult(g_,alfat);
    B1=pfc->mult(sell_pub.Y_[2],alfar);
    R1=R1+B1;
    A1=pfc->mult(show_info.derive.T1,alfar);
    R2=pfc->pairing(sell_pub.Y_[0],A1);
    pfc->start_hash();
    pfc->add_to_hash(show_info.derive.T1_);
    pfc->add_to_hash(show_info.derive.T3);
    pfc->add_to_hash(R1);
    pfc->add_to_hash(R2);
    show_info.pok4.c4=pfc->finish_hash_to_group();
    temp=pfc->Zpmulti(t,show_info.pok4.c4);
    show_info.pok4.st=pfc->Zpsub(alfat,temp);
    temp=pfc->Zpmulti(tick_pri.dsrnd,show_info.pok4.c4);
    show_info.pok4.sr=pfc->Zpsub(alfar,temp);

    show_info.dsid=tick_pri.dsid;
    show_info.VP_t=tick.VP_t;
    return 0;

}
int EPET::ValidTick(SELLER_PUB_KEY &sell_pub, USER_SHOW_INFO &show_info,BLAME_INFO &blame_info)
{
    //verify urs
    GT E1,E2,E3;
    G1 A1;
    G2 B1,B2;
    pfc->add_to_hash(show_info.derive.T1_);
    pfc->add_to_hash(show_info.derive.T2_);
    pfc->add_to_hash(show_info.derive.T1);
    pfc->add_to_hash(show_info.derive.T2);
    pfc->add_to_hash(show_info.derive.T3);
    Big c=pfc->finish_hash_to_group();
    A1= pfc->mult(show_info.derive.T1,show_info.derive.s);
    E1=pfc->pairing(sell_pub.Y_[0],A1);

    E2= pfc->pairing(g_,show_info.derive.T2);
    E2=pfc->power(E2,c);
    E2= E2*show_info.derive.T3;

    B1=sell_pub.X_+show_info.derive.T1_;
    B2=pfc->mult(sell_pub.Y_[1],show_info.dsid);
    B1=B2+B1;
    B2=pfc->mult(sell_pub.Y_[3],show_info.VP_t);
    B1=B2+B1;
    E3=pfc->pairing(B1,show_info.derive.T1);
    E3=pfc->power(E3,c);
    E1=E1*E3;
    if(E1 != E2) return 1;
    A1=sell_pub.Y[0]+sell_pub.Y[1]+sell_pub.Y[3];
    E1=pfc->pairing(show_info.derive.T1_,A1);
    E2=pfc->pairing(show_info.derive.T2_,g);
    if(E1 != E2) return 2;

    //verify pok4
    G2 R1;
    GT R2;
    R1=pfc->mult(g_,show_info.pok4.st);
    B1=pfc->mult(sell_pub.Y_[2],show_info.pok4.sr);
    B2=pfc->mult(show_info.derive.T1_,show_info.pok4.c4);
    R1=R1+B1+B2;
    R2=pfc->pairing(sell_pub.Y_[0],show_info.derive.T1);
    R2=pfc->power(R2,show_info.pok4.sr);
    E1=pfc->power(show_info.derive.T3,show_info.pok4.c4);
    R2=R2*E1;
    pfc->start_hash();
    pfc->add_to_hash(show_info.derive.T1_);
    pfc->add_to_hash(show_info.derive.T3);
    pfc->add_to_hash(R1);
    pfc->add_to_hash(R2);
    Big c4=pfc->finish_hash_to_group();
    if(c4 != show_info.pok4.c4) return 3;
    blame_info.dstag=show_info.dsid;
    blame_info.c=c;
    blame_info.s=show_info.derive.s;
    return 0;
}

//Trace Double-spending
int EPET::TraceDS(BLAME_INFO &blame_info1,BLAME_INFO &blame_info2,USER_KEY &user_key)
{
    if(blame_info1.dstag != blame_info2.dstag) return 1;
    Big a=pfc->Zpsub(blame_info1.s,blame_info2.s);
    Big b=pfc->Zpsub(blame_info2.c,blame_info1.c);
    Big c=pfc->Zpinverse(b);
    user_key.usk=pfc->Zpmulti(a,c);
    user_key.upk=pfc->mult(g,user_key.usk);
    return 0;

}
int EPET::VerifyDS(USER_KEY &user_key)//return 1 succ, 0 fail
{
    G1 upk=pfc->mult(g,user_key.usk);
    if(upk != user_key.upk) return 1;
    return 0;

}
