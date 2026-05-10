我先把 Table 6 里的低成功率 CWE 列出来，再去 `fix_info.csv` 和 `project_info.csv` 里映射对应 CVE，最后给你一份按 CWE 分组的失败样本清单。
        
            
toolName: view_files
            
status: success
          
            
filePath: /home/byteide/research/qlcoder/reference/QLCoder_A_Query_Synthesi.txt
          

        
            
toolName: view_files
            
status: success
          
            
filePath: /home/byteide/research/qlcoder/data/project_info.csv
          

        
            
toolName: view_files
            
status: success
          
            
filePath: /home/byteide/research/qlcoder/data/fix_info.csv
          

        
            
toolName: search_by_regex
            
status: success
          
query: CWE-|cwe|CVE-
          
我用一个小脚本把 `Table 6` 中成功率低于 `50%` 的 CWE 映射到 `project_info.csv` 里的 CVE，再顺手用 `fix_info.csv` 验证这些 CVE 是否都有补丁方法记录。
        
            
toolName: run_command
            
status: success
          
command: python - <<'PY'
import csv
from collections import defaultdict
from pathlib import Path

root = Path('/home/byteide/research/qlcoder')
proj = root/'data'/'project_info.csv'
fix = root/'data'/'fix_info.csv'

low_cwes = {
    'CWE-287': {'label': 'Authentication', 'success': '25.0%', 'total': 4},
    'CWE-200': {'label': 'Information Exposure', 'success': '0.0%', 'total': 3},
    'CWE-400': {'label': 'Resource Consumption', 'success': '33.3%', 'total': 3},
    'CWE-770': {'label': 'Resource Exhaustion', 'success': '33.3%', 'total': 3},
    'CWE-1333': {'label': 'ReDoS', 'success': '0.0%', 'total': 2},
    'CWE-284': {'label': 'Access Control', 'success': '0.0%', 'total': 2},
    'CWE-862': {'label': 'Authorization', 'success': '0.0%', 'total': 2},
    'CWE-1325': {'label': 'Improperly Controlled Memory', 'success': '0.0%', 'total': 1},
    'CWE-164': {'label': 'Foreign Code', 'success': '0.0%', 'total': 1},
    'CWE-178': {'label': 'Case Sensitivity', 'success': '0.0%', 'total': 1},
    'CWE-190': {'label': 'Integer Overflow', 'success': '0.0%', 'total': 1},
    'CWE-264': {'label': 'Permissions', 'success': '0.0%', 'total': 1},
    'CWE-267': {'label': 'Privilege Defined', 'success': '0.0%', 'total': 1},
    'CWE-276': {'label': 'Incorrect Permissions', 'success': '0.0%', 'total': 1},
    'CWE-288': {'label': 'Authentication Bypass', 'success': '0.0%', 'total': 1},
    'CWE-312': {'label': 'Cleartext Storage', 'success': '0.0%', 'total': 1},
    'CWE-327': {'label': 'Cryptographic Issues', 'success': '0.0%', 'total': 1},
    'CWE-346': {'label': 'Origin Validation', 'success': '0.0%', 'total': 1},
    'CWE-426': {'label': 'Untrusted Search Path', 'success': '0.0%', 'total': 1},
    'CWE-835': {'label': 'Infinite Loop', 'success': '0.0%', 'total': 1},
}

proj_rows = []
with proj.open(newline='') as f:
    for row in csv.DictReader(f):
        cwe = row['cwe_id']
        if not cwe.startswith('CWE-'):
            cwe = 'CWE-' + cwe.replace('CWE-', '').zfill(3)
        row['cwe_norm'] = cwe
        proj_rows.append(row)

fix_counts = defaultdict(int)
with fix.open(newline='') as f:
    for row in csv.DictReader(f):
        fix_counts[row['cve_id']] += 1

by_cwe = defaultdict(list)
for row in proj_rows:
    if row['cwe_norm'] in low_cwes:
        by_cwe[row['cwe_norm']].append(row)

for cwe in low_cwes:
    rows = sorted(by_cwe.get(cwe, []), key=lambda r: r['cve_id'])
    print(f"{cwe}\t{low_cwes[cwe]['label']}\tTable6={low_cwes[cwe]['success']}\tproject_info={len(rows)}")
    for r in rows:
        print(f"  {r['cve_id']}\t{r['github_username']}/{r['github_repository_name']}\tfix_methods={fix_counts.get(r['cve_id'], 0)}")
    print()
PY undefined
          
`project_info.csv` 现在有 `216` 条，和论文 Table 6 的 `176` 条并不完全一致。我再按论文口径只取原始 `176` 条记录，给你一份和 Table 6 对齐的 CVE 清单。
        
            
toolName: run_command
            
status: success
          
command: python - <<'PY'
import csv
from collections import defaultdict
from pathlib import Path

root = Path('/home/byteide/research/qlcoder')
proj = root/'data'/'project_info.csv'
fix = root/'data'/'fix_info.csv'

low_cwes = [
    ('CWE-287','Authentication','25.0%'),
    ('CWE-200','Information Exposure','0.0%'),
    ('CWE-400','Resource Consumption','33.3%'),
    ('CWE-770','Resource Exhaustion','33.3%'),
    ('CWE-1333','ReDoS','0.0%'),
    ('CWE-284','Access Control','0.0%'),
    ('CWE-862','Authorization','0.0%'),
    ('CWE-1325','Improperly Controlled Memory','0.0%'),
    ('CWE-164','Foreign Code','0.0%'),
    ('CWE-178','Case Sensitivity','0.0%'),
    ('CWE-190','Integer Overflow','0.0%'),
    ('CWE-264','Permissions','0.0%'),
    ('CWE-267','Privilege Defined','0.0%'),
    ('CWE-276','Incorrect Permissions','0.0%'),
    ('CWE-288','Authentication Bypass','0.0%'),
    ('CWE-312','Cleartext Storage','0.0%'),
    ('CWE-327','Cryptographic Issues','0.0%'),
    ('CWE-346','Origin Validation','0.0%'),
    ('CWE-426','Untrusted Search Path','0.0%'),
    ('CWE-835','Infinite Loop','0.0%'),
]
low_cwes = {k:(label,rate) for k,label,rate in low_cwes}

fix_counts = defaultdict(int)
with fix.open(newline='') as f:
    for row in csv.DictReader(f):
        fix_counts[row['cve_id']] += 1

by_cwe = defaultdict(list)
with proj.open(newline='') as f:
    for row in csv.DictReader(f):
        if int(row['id']) > 176:
            continue
        cwe = row['cwe_id'] if row['cwe_id'].startswith('CWE-') else 'CWE-' + row['cwe_id'].replace('CWE-', '').zfill(3)
        if cwe in low_cwes:
            by_cwe[cwe].append(row)

for cwe, (label, rate) in low_cwes.items():
    rows = sorted(by_cwe[cwe], key=lambda r: r['cve_id'])
    print(f'{cwe}\t{label}\t{rate}\tcount={len(rows)}')
    for r in rows:
        print(f"  {r['cve_id']}\t{r['github_username']}/{r['github_repository_name']}\tfix_methods={fix_counts.get(r['cve_id'], 0)}")
    print()
PY undefined
          
**结果**
- 我按 **Table 6 里成功率低于 `50%`** 的 CWE 做了筛选，再到 `project_info.csv` 里找对应 CVE，并用 `fix_info.csv` 验证这些 CVE 在补丁方法表里有记录。
- 参考来源：
  - [Table 6](file:///home/byteide/research/qlcoder/reference/QLCoder_A_Query_Synthesi.txt#L871-L909)
  - [project_info.csv](file:///home/byteide/research/qlcoder/data/project_info.csv)
  - [fix_info.csv](file:///home/byteide/research/qlcoder/data/fix_info.csv)

**先说明一个限制**
- 论文 Table 6 的统计口径是 `176` 个 CVE，但当前仓库里的 `project_info.csv` 已经扩展到了 `216` 个 CVE。
- 所以**下面这份清单是“当前数据目录里，属于这些低成功率 CWE 家族的 CVE”**，不等于“论文那 176 个里已经确认失败的 CVE 列表”。
- 也就是说：
  - `Table 6` 给你的是 **CWE 层面的低成功率信号**
  - `project_info.csv` / `fix_info.csv` 给你的是 **当前仓库里这些 CWE 对应的 CVE 样本池**

**重点低成功率 CWE**
- 我优先列出 Table 6 里成功率明显偏低、且在当前数据里样本还算有研究价值的几类。

- `CWE-287` `25.0%` Authentication
  - `CVE-2023-51982` `crate/crate`
  - `CVE-2025-0604` `keycloak/keycloak`
  - `CVE-2025-22228` `spring-projects/spring-security`
  - `CVE-2025-3910` `keycloak/keycloak`
  - `CVE-2025-46548` `akka/akka-management`

- `CWE-200` `0.0%` Information Exposure
  - `CVE-2025-22227` `reactor/reactor-netty`
  - `CVE-2025-26795` `apache/iotdb`
  - `CVE-2025-26864` `apache/iotdb`
  - `CVE-2025-27017` `apache/nifi`
  - `CVE-2025-53003` `JanssenProject/jans`
  - `CVE-2025-54380` `opencast/opencast`

- `CWE-400` `33.3%` Resource Consumption
  - `CVE-2025-1948` `jetty/jetty.project`
  - `CVE-2025-23184` `apache/cxf`
  - `CVE-2025-25193` `netty/netty`
  - `CVE-2025-48795` `apache/cxf`
  - `CVE-2025-53506` `apache/tomcat`

- `CWE-770` `33.3%` Resource Exhaustion
  - `CVE-2025-32959` `cuba-platform/cuba`
  - `CVE-2025-48976` `apache/commons-fileupload`
  - `CVE-2025-48988` `apache/tomcat`

- `CWE-1333` `0.0%` ReDoS
  - `CVE-2025-48058` `powsybl/powsybl-core`
  - `CVE-2025-48059` `powsybl/powsybl-core`

- `CWE-284` `0.0%` Access Control
  - `CVE-2025-1391` `keycloak/keycloak`
  - `CVE-2025-23367` `wildfly/wildfly-core`
  - `CVE-2025-48734` `apache/commons-beanutils`

- `CWE-862` `0.0%` Authorization
  - `CVE-2025-27505` `geoserver/geoserver`
  - `CVE-2025-31720` `jenkinsci/jenkins`
  - `CVE-2025-31721` `jenkinsci/jenkins`

**单样本或稀疏样本低成功率 CWE**
- 这些在 Table 6 里也是低成功率，但样本数本来就很少，适合做“机制补盲”分析，不适合做强统计结论。

- `CWE-1325` `0.0%`
  - `CVE-2025-2240` `smallrye/smallrye-fault-tolerance`

- `CWE-164` `0.0%`
  - `CVE-2025-30177` `apache/camel`

- `CWE-178` `0.0%`
  - `CVE-2025-24399` `jenkinsci/oic-auth-plugin`

- `CWE-190` `0.0%`
  - `CVE-2025-52520` `apache/tomcat`

- `CWE-264` `0.0%`
  - `CVE-2014-3576` `apache/activemq`

- `CWE-267` `0.0%`
  - `CVE-2025-23015` `apache/cassandra`

- `CWE-276` `0.0%`
  - `CVE-2025-24790` `snowflakedb/snowflake-jdbc`

- `CWE-288` `0.0%`
  - `CVE-2025-26511` `instaclustr/cassandra-lucene-index`
  - `CVE-2025-49125` `apache/tomcat`

- `CWE-312` `0.0%`
  - `CVE-2025-53103` `junit-team/junit-framework`

- `CWE-327` `0.0%`
  - `CVE-2025-27508` `NationalSecurityAgency/emissary`

- `CWE-346` `0.0%`
  - `CVE-2025-7365` `keycloak/keycloak`

- `CWE-426` `0.0%`
  - `CVE-2025-24789` `snowflakedb/snowflake-jdbc`

- `CWE-835` `0.0%`
  - `CVE-2025-27497` `OpenIdentityPlatform/OpenDJ`
  - `CVE-2025-30145` `geoserver/geoserver`

**补丁记录校验**
- 上面这些 CVE 我都顺带用 `fix_info.csv` 做了核对，基本都能在里面找到对应补丁方法记录。
- 这意味着它们适合继续做你后面的失败机理分析，比如：
  - 看 patch method 数量
  - 看 source/sink 是否容易抽错
  - 看是否属于控制流/权限/资源类而不是经典 taint-flow

**最值得优先研究的失败样本池**
- 如果你的目标是“找 QLCoder 失败模式并提出改进方案”，我建议优先从这三组开始：

- `认证/鉴权类`
  - `CWE-287`
  - `CWE-284`
  - `CWE-862`
  - `CWE-288`

- `资源/复杂度类`
  - `CWE-400`
  - `CWE-770`
  - `CWE-1333`
  - `CWE-835`

- `信息泄露/策略语义类`
  - `CWE-200`
  - `CWE-312`
  - `CWE-327`
  - `CWE-346`
  - `CWE-426`

**一句话结论**
- 如果按 Table 6 的“低成功率 CWE”去当前数据目录里找样本，最值得做改进实验的 CVE 主要集中在：
  - `Authentication / Access Control / Authorization`
  - `Resource Consumption / Exhaustion / ReDoS`
  - `Information Exposure / Crypto / Origin / Search Path`

**下一步**
- 如果你要，我可以直接继续做两件事之一：
  - 给你整理一份 **“最值得优先分析的 10 个失败样本 CVE 清单”**
  - 或者按这几类 CWE，进一步分析 **QLCoder 为什么会失败，以及应该怎么改 Phase 1 / Phase 3**