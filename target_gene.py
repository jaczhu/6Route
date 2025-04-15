from collections import Counter,defaultdict
import math 
import time
from IPy import IP
import radix
import argparse
import sys
import random
def hex_to_dec(hex_str):  
    return int(hex_str, 16) 

def calculate_entropy(character_counts):  
    total = sum(character_counts.values())  
    if total == 0:  
        return 0  
    entropy = 0  
    for count in character_counts.values():  
        probability = count / total  
        entropy -= probability * math.log2(probability)  
    return entropy / 4  

def group_by_chars(strings, indices,fix_str):  
    if not indices:  
        # 如果没有更多的索引需要分组，就返回当前字符串列表  
        return {fix_str: list(strings)}  
  
    # 取出第一个索引，并对字符串列表进行分组  
    first_index = indices[0]
    groups = defaultdict(list) 
    for s in strings:  
        fix_str = fix_str[:first_index] + s[first_index] + fix_str[first_index+1:]
        groups[fix_str].append(s)
  
    # 递归地对每个分组进行进一步分组
    result = defaultdict(list)
    for key, sublist in groups.items():
        if len(sublist) == 1:
            result[key] = sublist
            continue
        else:
            subgroups = group_by_chars(sublist, indices[1:],key)
            for subgroup_key, subgroup_value in subgroups.items():
                result[subgroup_key] = subgroup_value
  
    return result

def string_to_ipv6(s):
    # 确保字符串长度为16
    assert len(s) == 16, "String must be 16 characters long"
      
    # 将字符串分成4组，每组4个字符
    groups = [s[i:i+4] for i in range(0, len(s), 4)]  
    return ':'.join(groups) + '::1234'
def replace_stars_with_hex(string, budget,prefix_list,index=0, file_handle=None):  
    """  
    递归地替换字符串中的 '*' 字符，并将所有可能的十六进制字符排列组合写入文件。  
      
    :param string: 包含 '*' 的输入字符串。  
    :param index: 当前要替换的 '*' 的索引。  
    :param file_handle: 用于写入结果的文件句柄。  
    """      
    # 如果已经处理完所有的 '*'，生成地址并写入文件  
    if '*' not in string: 
        if string not in prefix_list:
            file_handle.write(string_to_ipv6(string) + '\n')  
        return  
      
    # 否则，找到下一个 '*' 的位置  
    next_star_index = string.find('*', index)  
    
    # 替换当前 '*' 为所有可能的十六进制字符，并递归处理  
    for hex_char in '0123456789abcdef':
        new_string = string[:next_star_index] + hex_char + string[next_star_index+1:]  
        replace_stars_with_hex(new_string, prefix_list, next_star_index+1, file_handle)

def replace_stars(s, index=0):
    # 如果已经处理完所有字符，返回当前字符串
    if index == len(s):
        return [s]
    # 如果当前字符不是 '*', 递归处理下一个字符
    if s[index] != '*':
        return replace_stars(s, index + 1)
    # 如果当前字符是 '*', 替换为 '0' 到 'f' 的所有可能值
    result = []
    for char in '0123456789abcdef':
        # 替换当前 '*' 为 char，并递归处理下一个字符
        new_s = s[:index] + char + s[index + 1:]
        result.extend(replace_stars(new_s, index + 1))
    return result

def replace_chars(s, index_list):
    # 如果已经处理完所有字符，返回当前字符串
    if len(index_list) == 0:
        return [s]
    # 如果当前字符是 '*', 替换为 '0' 到 'f' 的所有可能值
    result = []
    index = index_list[0]
    for char in '0123456789abcdef':
        if index == 15:
            new_s = s[:index] + char
        else:
            new_s = s[:index] + char + s[index + 1:]
        result.extend(replace_chars(new_s, index_list[1:]))
    return result

def target_gene(prefix_ip, budget, dim, output_file):  
    generate_num = 0
    densities = []
    for key, value in prefix_ip.items():
        prefixes = set()
        prefix_len = int(key.split('/')[1])
        for ip in value:
            prefix64 = IP(ip).strFullsize().replace(":", "")[:16] 
            prefixes.add(prefix64)
        densities.append(len(prefixes) / 2 ** (64 - prefix_len))
    density_sum = sum(densities)
    #print(density_sum)
    #for key, value in prefix_ip.items():
    #    density = len(value) / 2 ** (64 - prefix_len)
    #    print(density)
    #    print(density / density_sum)
    #    budget = budget_all * density / density_sum
    #    print(budget)
    j = 0
    for key1, value1 in prefix_ip.items():
        j += 1
        prefix_len = int(key1.split('/')[1])
        prefixes=set()
        position_counters = {i: Counter() for i in range(16)}
        for ip in value1:
            prefix64 = IP(ip).strFullsize().replace(":", "")[:16] 
            prefixes.add(prefix64)
            for i, char in enumerate(prefix64):
                position_counters[i][char] += 1
        if len(prefixes) == 1:
            continue
        density = len(prefixes) / 2 ** (64 - prefix_len)
        budget = budget * density / density_sum
        print(key1, len(prefixes), budget)
        #print(budget)
        prefix_str = IP(value[0]).strFullsize().replace(":", "")[:16]
        entropies = {}
        fix_str = '****************'
        for i in range(16):
            character_counts = position_counters[i]
            entropy = calculate_entropy(character_counts)
            if entropy == 0:
                fix_str = fix_str[:i] + prefix_str[i] + fix_str[i+1:]
            entropies[i] = entropy
        sorted_entropy = sorted(entropies.items(), key = lambda x: x[1]) 
        indexes = []
        for index, entro in sorted_entropy:
            if entro == 0:
                continue
            else:
                indexes.append(index)
        with open(output_file,'a') as f:
            if len(indexes) <= dim:
                #print("len(indexes) <= dim!")
                for prefix in prefixes:
                    if budget <= 0:
                        break
                    result = replace_chars(prefix, indexes)
                    for new_prefix in result:
                        if new_prefix not in prefixes:
                            f.write(string_to_ipv6(new_prefix) + '\n')
                            generate_num += 1
                            budget -= 1
                            if budget <= 0:
                                break
                #if budget > 0:
                #print(budget)
                continue
            result = group_by_chars(prefixes, indexes[:-dim], fix_str)
            sorted_result=sorted(result.items(), key = lambda item: len(item[1]), reverse = True)
            for key2, value2 in sorted_result:
                if budget <= 0:
                    break
                if len(value2) == 1:
                    continue
                new_string = key2
                star_positions = [pos for pos, char in enumerate(key2) if char == '*']
                if len(star_positions) == 1:
                    print("len(star_positions) == 1!")
                    for hex_char in '0123456789abcdef':
                        new_prefix = new_string.replace('*', hex_char, 1)
                        if new_prefix not in prefixes:
                            f.write(string_to_ipv6(new_prefix) + '\n')
                            generate_num += 1
                            budget -= 1
                            if budget <= 0:
                                break
                else:
                    pattern = key2
                    for index in star_positions:
                        is_fix = True
                        reference_char = key2[index]
                        for prefix in value2:
                            if prefix[index] != reference_char:
                                is_fix = False
                                break
                        if is_fix:
                            pattern = pattern[:index] + reference_char + pattern[index + 1:]
                    result = replace_stars(pattern)
                    for new_prefix in result:
                        if new_prefix not in prefixes:
                            f.write(string_to_ipv6(new_prefix) + '\n')
                            generate_num += 1
                            budget -= 1
                            if budget <= 0:
                                break
        print(budget)

if __name__ == "__main__":
    parse=argparse.ArgumentParser()
    parse.add_argument('--addr_file', type=str, help='path of seed addresses')
    parse.add_argument('--prefix_file', type=str, help='path of prefixes')
    parse.add_argument('--output_file', type=str, help='path of output')
    parse.add_argument('--budget',type=int,help='quantity of addresses detected by each BGP')
    parse.add_argument('--dim',type=int, default=2, help='dimension of target generation')
    args=parse.parse_args()
    start_time = time.time()
    ip6Rtree = radix.Radix()
    prefix_ip=defaultdict(list)
    prefixes=set()
    with open(args.prefix_file,'r') as f:
        for line in f:
            if line.strip() not in prefixes:
                prefixes.add(line.strip())
                try:
                    rnode = ip6Rtree.add(line.strip())
                except ValueError as e:
                    print(f"Invalid input: {line.strip()}")
                    sys.exit()
    with open(args.addr_file,'r') as f:
        for line in f:
            if line[0]=='#':
                continue
            ip=line.strip()
            try:
                node = ip6Rtree.search_best(ip)
                if (node == None):
                    continue
                prefix_ip[node.prefix].append(ip)
            except:
                    print(ip)
                    continue
    target_gene(prefix_ip,6000000, 1, args.output_file)
    end_time = time.time()
    elapsed_time = end_time - start_time
    print(elapsed_time)