
from random import randint

import asyncio
from asyncio_pool import AioPool
from scapy.sendrecv import sr1, send, srp, srp1, sr
from scapy.layers.inet import IP, ICMP, TCP

def tcp_task():
    #随机产生一个1-65535的IP的id位
    ip_id=randint(1,65535)
    data = "m"*1400  # 一个最大传输单元（MTU）为1500字节，减去ip头20字节，再减去tcp头20字节，最大可传输数据为1460字节
    pkt = IP(dst='192.168.214.129', id=ip_id) / TCP(dport=8080, flags="S")/data.encode(encoding="utf-8")
    #  发送包，超时时间为1秒，如果对端没有响应，则返回None，有响应则返回响应包
    res = sr1(pkt, timeout=1, verbose=False)
    return res

async def  tcp_worker():
    loop = asyncio.get_running_loop()
    res = await loop.run_in_executor(None, tcp_task)
    if res:
        # tcp = res.show()
        flags = res[1].flags #  flags为RA（RST/ACK）表示目标主机存活且探测的端口未开放
                                     #  flags为SA（SYN/ACK）表示目标主机存活且探测的端口开放
        print(flags)
    return res

async def spawn(work_num, size):
    """
    @param: work_num 总任务数量
    @param: size 每秒执行任务数
    """
    futures = []
    async with AioPool(size=size) as pool:
        for i in range(work_num):
            f = await pool.spawn(tcp_worker())
            futures.append(f)

if __name__ == "__main__":
    asyncio.get_event_loop().run_until_complete(asyncio.gather(spawn(1000000000000, 5000)))
