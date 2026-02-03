from generate_updates import resfileHandler
import collections
import matplotlib.pyplot as plt
import numpy as np

def statistic(file):
    valid=0
    invalid=0
    notfound=0
    reslist = resfileHandler(file)
    for r in reslist:
        if r[2]=="VALID":
            valid+=1
        elif r[2]=="INVALID":
            invalid+=1
        elif r[2]=="NOTFOUND":
            notfound+=1
    total = valid+invalid+notfound
    print("%d,%d,%d"%(valid,invalid,notfound))
    print("%f,%f,%f"%(valid/total,invalid/total,notfound/total))
    # print("valid: %d (percent : %f)"%(valid,valid/total))
    # print("invalid: %d (percent : %f)"%(invalid,invalid/total))
    # print("notfound: %d (percent : %f)"%(notfound,notfound/total))


def statisticPeak(file):
    d = dict()
    f = open(file,"r")
    for line in f:
        t = int(line.strip().split(".")[0])
        d[t] = d.get(t,0)+1
    sorted_dict = collections.OrderedDict(sorted(d.items(), key=lambda x: x[0]))
    for key,val in sorted_dict.items():
        print("%d,%d"%(key,val))

def draw_pic(data,res):
    # 创建直方图
    plt.hist(data, bins=128, edgecolor='black')

    # 添加标题和标签
    plt.title('Distribution of Array Elements')
    plt.xlabel('Value')
    plt.ylabel('Frequency')

    # 显示图表
    plt.savefig(res)


def statisticCheckTime(file):
    f = open(file,"r")
    times = []
    for line in f:
        times.append(int(line.strip()))
    sorted_data = np.sort(times)
    draw_pic(sorted_data,"./info_binary_serach_child.jpg")

def statisticCheckPath(file):
    f = open(file,"r")
    sot = 0
    leafnode = 0
    pb = 0
    total_hash = 0
    for line in f:
        if "SOT HIT" in line:
            sot+=1
        elif "FIND ROA" in line:
            leafnode+=1
        else:
            pb+=1
        data = line.strip().split(" ")
        total_hash+=int(data[-1])
    f.close()
    print(sot)
    print(leafnode)
    print(pb)
    print(total_hash)

def statisticTimeConsume(file):
    print(file)
    f = open(file,"r")
    validtime = []
    invalidtime = []
    notfoundtime = []
    for line in f:
        data = line.strip().split("|")
        if data[-1]=="VALID":
            validtime.append(float(data[-2]))
        elif data[-1]=="INVALID":
            invalidtime.append(float(data[-2]))
        elif data[-1]=="NOTFOUND":
            notfoundtime.append(float(data[-2]))
   
    sorted_data = np.sort(notfoundtime)

    # 计算CCDF
    ccdf = 1.0 - np.arange(1, len(sorted_data)+1) / len(sorted_data)

    # 绘制CCDF图
    plt.figure(figsize=(10, 6))
    plt.plot(sorted_data, ccdf, marker='.', linestyle='none')
    plt.yscale('log')
    plt.xscale('log')
    plt.xlabel('Value')
    plt.ylabel('CCDF')
    plt.title('Complementary Cumulative Distribution Function (CCDF)')
    plt.grid(True)
    plt.savefig("./show-nf.jpg")
    
def statisticCheckMode(file):
    f = open(file,"r")
    s = dict()
    for line in f:
        data = line.strip().split("---")
        arr = data[0].split(",")
        key = data[1]+f"|{len(arr)-1}"
        s[key] = s.get(key,0)+1
        
    sorted_d = sorted(s.items(),key=lambda item: item[1])
    for (key,val) in sorted_d:
        print("%s:%d"%(key,val))
    f.close()
    
    
def checkvrp(roaTypes:dict,filename):
    f = open(filename,"r")
    isp = 0
    business = 0
    gov = 0
    cloud = 0
    edu = 0
    notequal = set()
    for line in f:
        data = line.strip().split(" ")
        asn = data[1]
        if roaTypes.get(asn)==None:
            notequal.add(asn)
            # print(line)
            continue
        if roaTypes[asn] == "ISP":
            isp+=1
        elif roaTypes[asn] == "Business":
            business+=1
        elif roaTypes[asn] == "Education":
            edu+=1
        elif roaTypes[asn] == "Cloud":
            cloud+=1
        elif roaTypes[asn] == "Government":
            gov+=1
    return isp,business,gov,cloud,edu,notequal

def statisticROA():
    f = open("./roa_type.txt","r")
    roaTypes = dict()
    for line in f:
       data = line.strip().split(" ")
       roaTypes[data[0]]=data[1]
    f.close()
    # print(roaTypes)
    isp4,business4,gov4,cloud4,edu4,ne4 = checkvrp(roaTypes,"./test_data/nsdi_exp/v4/vrp.txt")
    isp6,business6,gov6,cloud6,edu6,ne6 = checkvrp(roaTypes,"./test_data/nsdi_exp/v6/vrp.txt")
    print(isp4+isp6)
    print(business4+business6)
    print(gov4+gov6)
    print(cloud4+cloud6)
    print(edu4+edu6)      
    # print("notfound")  
    # for n in ne4.union(ne6):
    #     print(n)
        
if __name__=="__main__":
    # statisticROA()
    # statisticCheckPath("./hash_time.txt")
    # statisticCheckTime("./leafnode_cmp.txt")
    # statisticCheckMode("./leafnode.txt")
    # statisticTimeConsume("./single-validation.txt")
    # statistic("./test_data/test_result/trov/v6/result.txt")
    statistic("./test_data/test_result/trov/v6/result.txt")
    # statistic("./test_data/test_result/")
    # statisticPeak("./ris.txt")