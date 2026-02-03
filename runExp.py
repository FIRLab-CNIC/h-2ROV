import os
import csv
from time import sleep
from generate_updates import generate_mixedIP, generate_mixedIP_raw, generate_mixedSize_raw
import datetime
from dateutil.relativedelta import relativedelta
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

TURN = 1

methods = {
    "trov":"trov",
    "hbasic":"hbasic",
    "hbinary":"hbinary",
    "hnlb":"hnlb",
    "bird":"bird",
    "bird_trie":"bird_trie",
    "bgp-srx":"bgp-srx"
}

def result_cal(result_file) -> float:
    f = open(result_file,"r")
    res = 0
    line_counts = 0
    for line in f:
        res += float(line.strip())
        line_counts+=1
    res = res/line_counts
    f.close()
    return res    

def runExp_split(method,insert_file,validate_file,result_file,threshold, cpu_id=None) -> float:
    i=0
    while i<TURN:
        command = f"./main -a {method} -m bash -i {insert_file} -v {validate_file}  -r {result_file} -w {threshold}"
        if cpu_id is not None:
            command = f"taskset -c {cpu_id} {command}"
        print(command)
        os.system(command)
        i+=1
        print("%d-th turn"%(i))
    resfile = f"./result_data/validate_{method}"
    res = result_cal(resfile)
    os.system(f"rm {resfile}")
    return res


def speedTest(vrpfile, uptfile, withdrawfile, resfile, cpu_id=None):
    res = dict()
    widelen = 8
    def wrap_cmd(cmd):
        if cpu_id is not None:
            return f"taskset -c {cpu_id} {cmd}"
        else:
            return cmd
    # res["hbasic"] = runExp_split(methods["hbasic"],vrpfile,uptfile,"./test_data/test_result/hbasic/v4/result.txt",5)
    res["hnlb"] = runExp_split(methods["hnlb"],vrpfile,uptfile,"./test_data/test_result/hnlb/v4/result.txt",widelen, cpu_id)
    res["trov"] = runExp_split(methods["trov"],vrpfile,uptfile,"./test_data/test_result/trov/v4/result.txt",widelen, cpu_id)
    res["bird"] = runExp_split(methods["bird"],vrpfile,uptfile,"./test_data/test_result/bird/v4/result.txt",widelen, cpu_id)
    res["bird_trie"] = runExp_split(methods["bird_trie"],vrpfile,uptfile,"./test_data/test_result/bird_trie/v4/result.txt",widelen, cpu_id)
    res["bgp-srx"] = runExp_split(methods["bgp-srx"],vrpfile,uptfile,"./test_data/test_result/bgp-srx/v4/result.txt",widelen, cpu_id)
    f = open(resfile,"w")
    for group,method in res.items():
        f.writelines("%s,%f\n"%(group,method))
    f.close()

def speedTest6(vrpfile,uptfile,resfile):
    res = dict()
    widelen = 8
    # res["hbasic"] = runExp_split(methods["hbasic"],vrpfile,uptfile,"./test_data/test_result/hbasic/v4/result.txt",5)
    res["hnlb"] = runExp_split(methods["hnlb"],vrpfile,uptfile,"./test_data/test_result/hnlb/v6/result.txt",7)
    res["trov"] = runExp_split(methods["trov"],vrpfile,uptfile,"./test_data/test_result/trov/v6/result.txt",widelen)
    res["bird"] = runExp_split(methods["bird"],vrpfile,uptfile,"./test_data/test_result/bird/v6/result.txt",widelen)
    res["bird_trie"] = runExp_split(methods["bird_trie"],vrpfile,uptfile,"./test_data/test_result/bird_trie/v6/result.txt",widelen)
    res["bgp-srx"] = runExp_split(methods["bgp-srx"],vrpfile,uptfile,"./test_data/test_result/bgp-srx/v6/result.txt",widelen)
    f = open(resfile,"w")
    for group,method in res.items():
        f.writelines("%s,%f\n"%(group,method))
    f.close()

def wideLenTest(vrpfile,uptfile,resfile):
    res = dict()
    for i in range(1,15):
        widelen = i
        res[f"hbasic_{widelen}"] = runExp_split(methods["hbasic"],vrpfile,uptfile,"./test_data/test_result/hbasic/v4/result.txt",widelen)
    for i in range(1,15):
        widelen = i
        res[f"hnlb_{widelen}"] = runExp_split(methods["hnlb"],vrpfile,uptfile,"./test_data/test_result/hnlb/v4/result.txt",widelen)
    f = open(resfile,"w")
    for group,method in res.items():
        f.writelines("%s,%f\n"%(group,method))
    f.close()

def ROVresultTest():
    vrpfile = "./test_data/nsdi_exp_20240825/v4/roa_20240825_v4.txt"
    folder = "./test_data/nsdi_exp_20240825/v4/gUpt/"
    pd = sorted(os.listdir(folder))
    res = dict()
    for p in pd:
        uptfile = folder+"/"+p
        key = p[0:-4]
        res[key] = dict()
        # res[key]["hbasic"] = runExp_split(methods["hbasic"],vrpfile,uptfile,"./test_data/test_result/hbasic/v4/result.txt",8)
        # res[key]["hnlb"] = runExp_split(methods["hnlb"],vrpfile,uptfile,"./test_data/test_result/hnlb/v4/result.txt",7)
        # res[key]["trov"] = runExp_split(methods["trov"],vrpfile,uptfile,"./test_data/test_result/trov/v4/result.txt",8)
        # res[key]["bird"] = runExp_split(methods["bird"],vrpfile,uptfile,"./test_data/test_result/bird/v4/result.txt",8)
        # res[key]["bird_trie"] = runExp_split(methods["bird_trie"],vrpfile,uptfile,"./test_data/test_result/bird_trie/v4/result.txt",8)
        res[key]["bgp-srx"] = runExp_split(methods["bgp-srx"],vrpfile,uptfile,"./test_data/test_result/bgp-srx/v4/result.txt",8)
    fieldnames = ["group","bgp-srx"]
    # fieldnames = ["group","hnlb","trov","bird","bird_trie","bgp-srx"]
    rows = [fieldnames]
    for group,method in sorted(res.items()):
        row = [group] + [method[field] for field in fieldnames[1:]]
        rows.append(row)
    
    with open("nsdi_v6_vary_bgp-srx.csv", "w", newline="") as f:
        writer = csv.writer(f)
        for row in rows:
            writer.writerow(row)

def IPmixedresultTest():
    vrpfile = "./test_data/nsdi_exp_20240825/mixed/roa.txt"
    ratio_v4 = 0
    res = dict()
    while ratio_v4<=100:
        key = f"{ratio_v4}_{100-ratio_v4}"
        res[key] = dict()
        for i in range(0,100):
            uptfile = generate_mixedIP_raw(ratio_v4)
            os.system("taskset -c 7 ./main -a %s -m bash -i %s -v %s  -r %s -w %d"%(methods["hnlb"],vrpfile,uptfile,"./test_data/test_result/hnlb/v4/result.txt",7))
            os.system("taskset -c 7 ./main -a %s -m bash -i %s -v %s  -r %s -w %d"%(methods["trov"],vrpfile,uptfile,"./test_data/test_result/trov/v4/result.txt",8))
            os.system("taskset -c 7 ./main -a %s -m bash -i %s -v %s  -r %s -w %d"%(methods["bird"],vrpfile,uptfile,"./test_data/test_result/bird/v4/result.txt",8))
            os.system("taskset -c 7 ./main -a %s -m bash -i %s -v %s  -r %s -w %d"%(methods["bird_trie"],vrpfile,uptfile,"./test_data/test_result/bird_trie/v4/result.txt",8))
            os.system("taskset -c 7 ./main -a %s -m bash -i %s -v %s  -r %s -w %d"%(methods["bgp-srx"],vrpfile,uptfile,"./test_data/test_result/bgp-srx/v4/result.txt",8))
        res[key]["hnlb"] = result_cal("./result_data/validate_"+methods["hnlb"])
        res[key]["trov"] = result_cal("./result_data/validate_"+methods["trov"])
        res[key]["bird"] = result_cal("./result_data/validate_"+methods["bird"])
        res[key]["bird_trie"] = result_cal("./result_data/validate_"+methods["bird_trie"])
        res[key]["bgp-srx"] = result_cal("./result_data/validate_"+methods["bgp-srx"]) 
        os.system(f"rm ./result_data/validate_*")
        ratio_v4+=10
    fieldnames = ["group","hnlb","trov","bird","bird_trie","bgp-srx"]
    # fieldnames = ["group","bgp-srx"]
    rows = [fieldnames]
    for group,method in sorted(res.items()):
        row = [group] + [method[field] for field in fieldnames[1:]]
        rows.append(row)
    
    with open("nsdi_mixedIP_new.csv", "w", newline="") as f:
        writer = csv.writer(f)
        for row in rows:
            writer.writerow(row)

def ROVsizerangeTest():
    vrpfile = "./test_data/nsdi_exp_20240825/v4/roa_20240825_v4.txt"
    sizes = [10000,100000,1000000]
    res = dict()
    for s in sizes:
        key = s
        res[key] = dict()
        for i in range(0,1):
            uptfile = generate_mixedSize_raw(s,4)
            os.system("taskset -c 7 ./main -a %s -m bash -i %s -v %s  -r %s -w %d"%(methods["hnlb"],vrpfile,uptfile,"./test_data/test_result/hnlb/v4/result.txt",8))
            os.system("taskset -c 7 ./main -a %s -m bash -i %s -v %s  -r %s -w %d"%(methods["trov"],vrpfile,uptfile,"./test_data/test_result/trov/v4/result.txt",8))
            os.system("taskset -c 7 ./main -a %s -m bash -i %s -v %s  -r %s -w %d"%(methods["bird"],vrpfile,uptfile,"./test_data/test_result/bird/v4/result.txt",8))
            os.system("taskset -c 7 ./main -a %s -m bash -i %s -v %s  -r %s -w %d"%(methods["bird_trie"],vrpfile,uptfile,"./test_data/test_result/bird_trie/v4/result.txt",8))
            os.system("taskset -c 7 ./main -a %s -m bash -i %s -v %s  -r %s -w %d"%(methods["bgp-srx"],vrpfile,uptfile,"./test_data/test_result/bgp-srx/v4/result.txt",8))
        res[key]["hnlb"] = result_cal("./result_data/validate_"+methods["hnlb"])
        res[key]["trov"] = result_cal("./result_data/validate_"+methods["trov"])
        res[key]["bird"] = result_cal("./result_data/validate_"+methods["bird"])
        res[key]["bird_trie"] = result_cal("./result_data/validate_"+methods["bird_trie"])
        res[key]["bgp-srx"] = result_cal("./result_data/validate_"+methods["bgp-srx"])
        os.system(f"rm ./result_data/validate_*")
    fieldnames = ["group","hnlb","trov","bird","bird_trie","bgp-srx"]
    rows = [fieldnames]
    for group,method in sorted(res.items()):
        row = [group] + [method[field] for field in fieldnames[1:]]
        rows.append(row)
    
    with open("nsdi_v4_sizerange_unique.csv", "w", newline="") as f:
        writer = csv.writer(f)
        for row in rows:
            writer.writerow(row)

# def runSerial(vrpfile,uptfold,resfold):
#     pd = sorted(os.listdir(uptfold))
#     for p in pd:
#         resfile = f"{resfold}/{p}.csv"
#         speedTest6(vrpfile,uptfold+"/"+p,resfile)

def self_cmp_serial():
    vrpfile = "./test_data/nsdi_exp_20240825/v4/roa_20240825_v4.txt"
    uptfold = "./test_data/nsdi_exp_20240825/v4/updates"
    resfold = "self_cmp_res_v4_range"
    runSerial(vrpfile,uptfold,resfold)
    vrpfile = "./test_data/nsdi_exp_20240825/v6/roa_20240825_v6.txt"
    uptfold = "./test_data/nsdi_exp_20240825/v6/updates"
    resfold = "self_cmp_res_v6_range"
    runSerial(vrpfile,uptfold,resfold)

def wideLen_exp():
    vrpfile = "./test_data/nsdi_exp_20240825/v4/roa_20240825_v4.txt"
    uptfile = "./test_data/nsdi_exp_20240825/v4/updates/rrc00.txt"
    # resfile = "./rrc00_future_v4.csv"
    resfile = "./memory_widelen_v4_larger.csv"
    # speedTest(vrpfile,uptfile,resfile)
    wideLenTest(vrpfile,uptfile,resfile)
    vrpfile = "./test_data/nsdi_exp_20240825/v6/roa_20240825_v6.txt"
    uptfile = "./test_data/nsdi_exp_20240825/v6/updates/rrc00.txt"
    # resfile = "./rrc00_future_v4.csv"
    resfile = "./memory_widelen_v6_larger.csv"
    # speedTest(vrpfile,uptfile,resfile)
    wideLenTest(vrpfile,uptfile,resfile)

def cmp_v6():
    vrpfile = "./test_data/nsdi_exp_20240825/v6/roa_20240825_v6.txt"
    uptfold = "./test_data/nsdi_exp_20240825/v6/updates"
    resfold = "./multi_rrc_res_v6_new"
    runSerial(vrpfile,uptfold,resfold)

def runSerial():
    pre = datetime.datetime(2020,1,1,0,0)
    end = datetime.datetime(2025,7,1,0,0)
    while pre<=end:
        vrpfile = f"./test_data/roa_monthly/v4/{pre.strftime('%Y%m%d')}.txt"
        updfile = f"./test_data/updates_monthly/v4/{pre.strftime('%Y%m%d')}.txt"
        speedTest(vrpfile,updfile,f"./rov_at_times_monthly/v4/{pre.strftime('%Y%m%d')}.csv")
        pre = pre+relativedelta(months=1)
    pre = datetime.datetime(2020,1,1,0,0)
    while pre<=end:
        vrpfile = f"./test_data/roa_monthly/v6/{pre.strftime('%Y%m%d')}.txt"
        updfile = f"./test_data/updates_monthly/v6/{pre.strftime('%Y%m%d')}.txt"
        speedTest6(vrpfile,updfile,f"./rov_at_times_monthly/v6/{pre.strftime('%Y%m%d')}.csv")
        pre = pre+relativedelta(months=1)


if __name__=="__main__":
    vrpfile = "./test_data/roa_20250701_v4.txt"
    upt_dir1 = "./test_data/20250701_1/v4"
    result_dir1 = "./result/v4"
    for uptfile in os.listdir(upt_dir1):
        uptfile_path = os.path.join(upt_dir1, uptfile)
        if os.path.isfile(uptfile_path):
            resfile = os.path.join(result_dir1, uptfile + ".csv")
            withdrawfile = ""
            print(f"Testing: {uptfile_path} -> {resfile}")
            speedTest(vrpfile, uptfile_path, withdrawfile, resfile)

    # upt_dir2 = "./test_data/20250701_2/v4"
    # result_dir2 = "./result_2/v4"
    # os.makedirs(result_dir2, exist_ok=True)
    # for uptfile in os.listdir(upt_dir2):
    #     uptfile_path = os.path.join(upt_dir2, uptfile)
    #     if os.path.isfile(uptfile_path):
    #         resfile = os.path.join(result_dir2, uptfile + ".csv")
    #         withdrawfile = ""
    #         print(f"Testing: {uptfile_path} -> {resfile}")
    #         speedTest(vrpfile, uptfile_path, withdrawfile, resfile)
    
    vrpfile6 = "./test_data/roa_20250701_v6.txt"
    upt_dir1 = "./test_data/20250701/v6"
    result_dir1 = "./result_1/v6"
    for uptfile in os.listdir(upt_dir1):
        uptfile_path = os.path.join(upt_dir1, uptfile)
        if os.path.isfile(uptfile_path):
            resfile = os.path.join(result_dir1, uptfile + ".csv")
            print(f"Testing: {uptfile_path} -> {resfile}")
            speedTest6(vrpfile6, uptfile_path, resfile)

    # upt_dir2 = "./test_data/20250701_2/v6"
    # result_dir2 = "./result_2/v6"
    # os.makedirs(result_dir2, exist_ok=True)
    # for uptfile in os.listdir(upt_dir2):
    #     uptfile_path = os.path.join(upt_dir2, uptfile)
    #     if os.path.isfile(uptfile_path):
    #         resfile = os.path.join(result_dir2, uptfile + ".csv")
    #         print(f"Testing: {uptfile_path} -> {resfile}")
    #         speedTest6(vrpfile6, uptfile_path, resfile)

    # runSerial()
    # cmp_v6()
    # vrpfile = "./test_data/roa_20250701_v4.txt"
    # uptfile = "./test_data/rib_20250701_v4.txt"
    # vrpfile = "./test_data/roa_20250701_v6.txt"
    # uptfile = "./test_data/rib_20250701_v6.txt"
    
   
    # runExp_split(methods["trov"],vrpfile,uptfile,"./test_data/test_result/trov/v4/result.txt",8)
    # runExp_split(methods["bird"],vrpfile,uptfile,"./test_data/test_result/bird/v4/result.txt",8)
    # runExp_split(methods["hnlb"],vrpfile,uptfile,"./test_data/test_result/hnlb/v4/result.txt",8)
    # runExp_split(methods["hbasic"],vrpfile,uptfile,"./test_data/test_result/hnlb/v4/result.txt",5)
    # runExp_split(methods["hnlb"],vrpfile,uptfile,"./test_data/test_result/hnlb/v4/result.txt",8)
    # uptfile = "./test_data/nsdi_exp_20240825/v6/updates/rrc00.txt"
    # runExp_split(methods["hbasic"],vrpfile,uptfile,"./test_data/test_result/hnlb/v6/result.txt",5)
    # runExp_split(methods["hnlb"],vrpfile,uptfile,"./test_data/test_result/hnlb/v6/result.txt",7)
