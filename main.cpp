#include"EPET.h"
#include "pairing_3.h"
#include <ctime>
#include <time.h>
#define TEST_TIME 1
int correct_test()
{
    PFC pfc(AES_SECURITY);

    EPET E_Tickets(&pfc);
    int ret =0;
    //1 SetUP
    PP pp;
    MSK msk;
    ret = E_Tickets.SetUp(pp,msk);
    if(ret != 0)
    {
        printf("E_Tickets.SetUp Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("E_Tickets.SetUp pass\n");

    //2 Seller key gen
    SELLER_KEY seller_key;
    ret = E_Tickets.SellerKG(seller_key);
    if(ret != 0)
    {
        printf("E_Tickets.SellerKG Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("E_Tickets.SellerKG pass\n");

    //3 User key gen

    USER_KEY user_key;
    ret = E_Tickets.UserKG(user_key);
    if(ret != 0)
    {
        printf("E_Tickets.UserKG Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("E_Tickets.UserKG pass\n");

    //4 User Obtain Cred
    POK1 pok1;
    USER_ATTR attr;
    Big VP_u;
    CRED_U cred_u;
    ///User Send proof
    ret = E_Tickets.GenerateAttributes(attr);
    if(ret != 0)
    {
        printf("E_Tickets.GenerateAttributes Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("E_Tickets.GenerateAttributes pass\n");
    ret=E_Tickets.ObtainCred_u_Send(user_key,pok1);
    if(ret != 0)
    {
        printf("E_Tickets.ObtainCred_u_Send Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("E_Tickets.ObtainCred_u_Send pass\n");

    ///CA Verify and issue cred
    ret =E_Tickets.IssueCred_u(user_key.upk,attr,pok1,msk,VP_u,cred_u);
    if(ret != 0)
    {
        printf("E_Tickets.IssueCred_u Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("E_Tickets.IssueCred_u pass\n");
    ///user verify cred
    ret =E_Tickets.ObtainCred_u_Receive(pp,cred_u,user_key.usk,attr,VP_u);
    if(ret != 0)
    {
        printf("E_Tickets.ObtainCred_u_Receive Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("E_Tickets.ObtainCred_u_Receive pass\n");
    //5 seller obtain cred
    POK2 pok2;
    CRED_S cred_s;
    ///seller send proof
    ret =E_Tickets.ObtainCred_s_Send(seller_key,pok2);
    if(ret != 0)
    {
        printf("E_Tickets.ObtainCred_s_Send Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("E_Tickets.ObtainCred_s_Send pass\n");
    /// CA verify and issue cred
    ret = E_Tickets.IssueCred_s(seller_key.pub_key,pok2,pp,msk,cred_s);
    if(ret != 0)
    {
        printf("E_Tickets.IssueCred_s Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("E_Tickets.IssueCred_s pass\n");
    /// seller verify cred
    ret =E_Tickets.ObtainCred_s_Receive(seller_key.pub_key,cred_s,pp);
    if(ret != 0)
    {
        printf("E_Tickets.ObtainCred_s_Receive Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("E_Tickets.ObtainCred_s_Receive pass\n");
    ret = E_Tickets.VerifySellerCred_s(seller_key.pub_key,cred_s,pp);
    if(ret != 0)
    {
        printf("E_Tickets.VerifySellerCred_s Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("E_Tickets.VerifySellerCred_s pass\n");
    //6 user obtain tickets
    TICK_PRI tick_pri;
    TICKET tick;
    USER_PURCH_INFO purch_info;

    ///user send proof
    ret = E_Tickets.ObtainTick_Send(pp,seller_key.pub_key,user_key,cred_u,attr,VP_u,tick_pri,purch_info);
    if(ret != 0)
    {
        printf("E_Tickets.ObtainTick_Send Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("E_Tickets.ObtainTick_Send pass\n");
    /// seller verify and issue ticket
    ret = E_Tickets.IssueTick(pp,purch_info,seller_key,tick);
    if(ret != 0)
    {
        printf("E_Tickets.IssueTick Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("E_Tickets.IssueTick pass\n");
    /// user verify ticket
    ret =E_Tickets.ObtainTick_Receive(seller_key.pub_key,user_key,tick_pri,tick);
    if(ret != 0)
    {
        printf("E_Tickets.ObtainTick_Receive Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("E_Tickets.ObtainTick_Receive pass\n");
    //7 user Show tick
    USER_SHOW_INFO show_info1,show_info2;
    BLAME_INFO blame_info1,blame_info2;
    ///user send proof
    ret=E_Tickets.ShowTick(seller_key.pub_key,tick_pri,tick,user_key,show_info1);
    if(ret != 0)
    {
        printf("E_Tickets.ShowTick1 Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("E_Tickets.ShowTick1 pass\n");
    ///verifier verify
    ret=E_Tickets.ValidTick(seller_key.pub_key,show_info1,blame_info1);
    if(ret != 0)
    {
        printf("E_Tickets.ValidTick1 Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("E_Tickets.ValidTick1 pass\n");

    ///user send proof
    ret=E_Tickets.ShowTick(seller_key.pub_key,tick_pri,tick,user_key,show_info2);
    if(ret != 0)
    {
        printf("E_Tickets.ShowTick2 Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("E_Tickets.ShowTick2 pass\n");
    ///verifier verify
    ret=E_Tickets.ValidTick(seller_key.pub_key,show_info2,blame_info2);
    if(ret != 0)
    {
        printf("E_Tickets.ValidTick2 Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("E_Tickets.ValidTick2 pass\n");
    //8 Trace and verify
    USER_KEY user_key_trace;

    ///trace
    ret = E_Tickets.TraceDS(blame_info1,blame_info2,user_key_trace);
    if(ret != 0)
    {
        printf("E_Tickets.TraceDS Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("E_Tickets.TraceDS pass\n");

    ///verify
    ret = E_Tickets.VerifyDS(user_key_trace);
    if(ret != 0)
    {
        printf("E_Tickets.VerifyDS Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("E_Tickets.VerifyDS pass\n");
    return 0;

}
int speed_test()
{
    int i;
    clock_t start,finish;
    double sum;
    PFC pfc(AES_SECURITY);

    EPET E_Tickets(&pfc);
    int ret =0;
    //1 SetUP
    PP pp;
    MSK msk;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret = E_Tickets.SetUp(pp,msk);
        if(ret != 0)
        {
            printf("E_Tickets.SetUp Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/CLOCKS_PER_SEC;
    printf("E_Tickets.SetUp ret : %d time =%f sec\n",ret,sum);

    //2 Seller key gen
    SELLER_KEY seller_key;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret = E_Tickets.SellerKG(seller_key);
        if(ret != 0)
        {
            printf("E_Tickets.SellerKG Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/CLOCKS_PER_SEC;
    printf("E_Tickets.SellerKG ret : %d time =%f sec\n",ret,sum);

    //3 User key gen

    USER_KEY user_key;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret = E_Tickets.UserKG(user_key);
        if(ret != 0)
        {
            printf("E_Tickets.UserKG Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/CLOCKS_PER_SEC;
    printf("E_Tickets.UserKG ret : %d time =%f sec\n",ret,sum);

    //4 User Obtain Cred
    POK1 pok1;
    USER_ATTR attr;
    Big VP_u;
    CRED_U cred_u;
    ///User Send proof
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret = E_Tickets.GenerateAttributes(attr);
        if(ret != 0)
        {
            printf("E_Tickets.GenerateAttributes Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/CLOCKS_PER_SEC;
    printf("E_Tickets.GenerateAttributes ret : %d time =%f sec\n",ret,sum);
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret=E_Tickets.ObtainCred_u_Send(user_key,pok1);
        if(ret != 0)
        {
            printf("E_Tickets.ObtainCred_u_Send Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/CLOCKS_PER_SEC;
    printf("E_Tickets.ObtainCred_u_Send ret : %d time =%f sec\n",ret,sum);

    ///CA Verify and issue cred
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret =E_Tickets.IssueCred_u(user_key.upk,attr,pok1,msk,VP_u,cred_u);
        if(ret != 0)
        {
            printf("E_Tickets.IssueCred_u Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/CLOCKS_PER_SEC;
    printf("E_Tickets.IssueCred_u ret : %d time =%f sec\n",ret,sum);
    ///user verify cred
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret =E_Tickets.ObtainCred_u_Receive(pp,cred_u,user_key.usk,attr,VP_u);
        if(ret != 0)
        {
            printf("E_Tickets.ObtainCred_u_Receive Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/CLOCKS_PER_SEC;
    printf("E_Tickets.ObtainCred_u_Receive ret : %d time =%f sec\n",ret,sum);
    //5 seller obtain cred
    POK2 pok2;
    CRED_S cred_s;
    ///seller send proof
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret =E_Tickets.ObtainCred_s_Send(seller_key,pok2);
        if(ret != 0)
        {
            printf("E_Tickets.ObtainCred_s_Send Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/CLOCKS_PER_SEC;
    printf("E_Tickets.ObtainCred_s_Send ret : %d time =%f sec\n",ret,sum);
    /// CA verify and issue cred
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret = E_Tickets.IssueCred_s(seller_key.pub_key,pok2,pp,msk,cred_s);
        if(ret != 0)
        {
            printf("E_Tickets.IssueCred_s Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/CLOCKS_PER_SEC;
    printf("E_Tickets.IssueCred_s ret : %d time =%f sec\n",ret,sum);
    /// seller verify cred
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret =E_Tickets.ObtainCred_s_Receive(seller_key.pub_key,cred_s,pp);
        if(ret != 0)
        {
            printf("E_Tickets.ObtainCred_s_Receive Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/CLOCKS_PER_SEC;
    printf("E_Tickets.ObtainCred_s_Receive ret : %d time =%f sec\n",ret,sum);
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret = E_Tickets.VerifySellerCred_s(seller_key.pub_key,cred_s,pp);
        if(ret != 0)
        {
            printf("E_Tickets.VerifySellerCred_s Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/CLOCKS_PER_SEC;
    printf("E_Tickets.VerifySellerCred_s ret : %d time =%f sec\n",ret,sum);
    //6 user obtain tickets
    TICK_PRI tick_pri;
    TICKET tick;
    USER_PURCH_INFO purch_info;

    ///user send proof
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret = E_Tickets.ObtainTick_Send(pp,seller_key.pub_key,user_key,cred_u,attr,VP_u,tick_pri,purch_info);
        if(ret != 0)
        {
            printf("E_Tickets.ObtainTick_Send Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/CLOCKS_PER_SEC;
    printf("E_Tickets.ObtainTick_Send ret : %d time =%f sec\n",ret,sum);
    /// seller verify and issue ticket
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret = E_Tickets.IssueTick(pp,purch_info,seller_key,tick);
        if(ret != 0)
        {
            printf("E_Tickets.IssueTick Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/CLOCKS_PER_SEC;
    printf("E_Tickets.IssueTick ret : %d time =%f sec\n",ret,sum);
    /// user verify ticket
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret =E_Tickets.ObtainTick_Receive(seller_key.pub_key,user_key,tick_pri,tick);
        if(ret != 0)
        {
            printf("E_Tickets.ObtainTick_Receive Erro ret =%d i=%d\n",ret,i);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/CLOCKS_PER_SEC;
    printf("E_Tickets.ObtainTick_Receive ret : %d time =%f sec\n",ret,sum);
    //7 user Show tick
    USER_SHOW_INFO show_info1,show_info2;
    BLAME_INFO blame_info1,blame_info2;
    ///user send proof
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret=E_Tickets.ShowTick(seller_key.pub_key,tick_pri,tick,user_key,show_info1);
        if(ret != 0)
        {
            printf("E_Tickets.ShowTick1 Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/CLOCKS_PER_SEC;
    printf("E_Tickets.ShowTick1 ret : %d time =%f sec\n",ret,sum);
    ///verifier verify
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret=E_Tickets.ValidTick(seller_key.pub_key,show_info1,blame_info1);
        if(ret != 0)
        {
            printf("E_Tickets.ValidTick1 Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/CLOCKS_PER_SEC;
    printf("E_Tickets.ValidTick1 ret : %d time =%f sec\n",ret,sum);

    ///user send proof
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret=E_Tickets.ShowTick(seller_key.pub_key,tick_pri,tick,user_key,show_info2);
        if(ret != 0)
        {
            printf("E_Tickets.ShowTick2 Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/CLOCKS_PER_SEC;
    printf("E_Tickets.ShowTick2 ret : %d time =%f sec\n",ret,sum);
    ///verifier verify
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret=E_Tickets.ValidTick(seller_key.pub_key,show_info2,blame_info2);
        if(ret != 0)
        {
            printf("E_Tickets.ValidTick2 Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/CLOCKS_PER_SEC;
    printf("E_Tickets.ValidTick2 ret : %d time =%f sec\n",ret,sum);
    //8 Trace and verify
    USER_KEY user_key_trace;

    ///trace
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret = E_Tickets.TraceDS(blame_info1,blame_info2,user_key_trace);
        if(ret != 0)
        {
            printf("E_Tickets.TraceDS Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/CLOCKS_PER_SEC;
    printf("E_Tickets.TraceDS ret : %d time =%f sec\n",ret,sum);

    ///verify
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret = E_Tickets.VerifyDS(user_key_trace);
        if(ret != 0)
        {
            printf("E_Tickets.VerifyDS Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/CLOCKS_PER_SEC;
    printf("E_Tickets.VerifyDS ret : %d time =%f sec\n",ret,sum);
    return 0;

}
int main()
{

/*
    int ret =correct_test();
    if(ret != 0)
    {

        printf("E_Tickets correct_test Erro ret =%d\n",ret);
        return 1;
    }
    else
    {
        printf("*******************************************\n");
        printf("E_Tickets correct_test pass\n");
    }
*/
    int ret =speed_test();
    if(ret != 0)
    {
        printf("E_Tickets speed_test Erro ret =%d\n",ret);
        return 1;
    }

    return 0;
}
