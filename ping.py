
from random import randint

import asyncio
from asyncio_pool import AioPool
from scapy.sendrecv import sr1, send, srp, srp1, sr
from scapy.layers.inet import IP, ICMP

def ping():
    #随机产生一个1-65535的IP的id位
    ip_id=randint(1,65535)
    #随机产生一个1-65535的icmp的id位
    icmp_id=randint(1,65535)
    #随机产生一个1-65535的icmp的序列号
    icmp_seq=randint(1,65535)
    pkt = IP(dst='192.168.214.1', ttl=64, id=ip_id) / ICMP(id=icmp_id, seq=icmp_seq)
    #  发送包，超时时间为1秒，如果对端没有响应，则返回None，有响应则返回响应包
    res = sr1(pkt, timeout=1, verbose=False)
    return res


async def  ping_worker():
    loop = asyncio.get_running_loop()
    res = await loop.run_in_executor(None, ping)
    if res:
        icmp = res[1][0]["ICMP"]
        echo_reply = icmp.type  # type=0: ping应答成功
        print(echo_reply, "echo")
        # s = res[1][0]["ICMP"].show()
        # print(s)
    print(res)
    return res

async def spawn(work_num, size):
    """
    @param: work_num 总任务数量
    @param: size 每秒执行任务数
    """
    futures = []
    async with AioPool(size=size) as pool:
        for i in range(work_num):
            f = await pool.spawn(ping_worker())
            futures.append(f)

if __name__ == "__main__":
    asyncio.get_event_loop().run_until_complete(asyncio.gather(spawn(1000000000000, 50000)))
