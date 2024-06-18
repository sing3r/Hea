# Weblogic 定时修改密码

## 1. 寻找 resetUserPassword 方法

按照以下步骤，基本上就可以找到 resetUserPassword 方法。

```shell
# 打开 wlst 工具
[oracle@8ffd4daff884 ~]$ ./weblogic/wlserver/common/bin/wlst.sh
## 连接 Weblogic
wls:/offline> connect('weblogic', 'welcome1', 't3://localhost:7001')
## 切换位置
wls:/offline> cd('/SecurityConfiguration/base_domain/Realms/myrealm/AuthenticationProviders/DefaultAuthenticator')
## 列出 MBean
wls:/offline> ls()
dr--   Realm

-r--   ControlFlag                                  REQUIRED
-r--   Description                                  WebLogic Authentication Provider
-r--   EnableGroupMembershipLookupHierarchyCaching  true
-r--   GroupHierarchyCacheTTL                       60
-r--   GroupMembershipSearching                     unlimited
-r--   KeepAliveEnabled                             false
-r--   MaxGroupHierarchiesInCache                   100
-r--   MaxGroupMembershipSearchLevel                0
-r--   MinimumPasswordLength                        8
-r--   Name                                         DefaultAuthenticator
-r--   PasswordDigestEnabled                        false
-r--   PropagateCauseForLoginException              false
-r--   ProviderClassName                            weblogic.security.providers.authentication.DefaultAuthenticationProviderImpl
-r--   SupportedExportConstraints                   java.lang.String[users, groups, passwords]
-r--   SupportedExportFormats                       java.lang.String[DefaultAtn]
-r--   SupportedImportConstraints                   java.lang.String[]
-r--   SupportedImportFormats                       java.lang.String[DefaultAtn]
-r--   SupportedUserAttributeNames                  java.lang.String[displayname, employeenumber, employeetype, givenname, homephone, mail, title, preferredlanguage, departmentnumber, facsimiletelephonenumber, mobile, pager, telephonenumber, postaladdress, street, l, st, postofficebox, c, homepostaladdress]
-r--   UseRetrievedUserNameAsPrincipal              false
-r--   Version                                      1.0

-r-x   addMemberToGroup                             Void : String(groupName),String(memberUserOrGroupName)
-r-x   advance                                      Void : String(cursor)
-r-x   changeUserPassword                           Void : String(userName),String(oldPassword),String(newPassword)
-r-x   close                                        Void : String(cursor)
-r-x   exportData                                   Void : String(format),String(filename),java.util.Properties
-r-x   getCurrentName                               String : String(cursor)
-r-x   getGroupDescription                          String : String(groupName)
-r-x   getSupportedUserAttributeType                javax.management.openmbean.OpenType : String(User)
-r-x   getUserAttributeValue                        Object : String(userName),String(userAttributeName)
-r-x   getUserDescription                           String : String(userName)
-r-x   groupExists                                  Boolean : String(groupName)
-r-x   haveCurrent                                  Boolean : String(cursor)
-r-x   importData                                   Void : String(format),String(filename),java.util.Properties
-r-x   isMember                                     Boolean : String(parentGroupName),String(memberUserOrGroupName),Boolean(recursive)
-r-x   isSet                                        Boolean : String(propertyName)
-r-x   isUserAttributeNameSupported                 Boolean : String(User)
-r-x   listAllUsersInGroup                          String[] : String(groupName),String(userNameWildcard),Integer(maximumToReturn)
-r-x   listGroupMembers                             String : String(groupName),String(memberUserOrGroupNameWildcard),Integer(maximumToReturn)
-r-x   listGroups                                   String : String(groupNameWildcard),Integer(maximumToReturn)
-r-x   listMemberGroups                             String : String(memberUserOrGroupName)
-r-x   listUsers                                    String : String(userNameWildcard),Integer(maximumToReturn)
-r-x   removeGroup                                  Void : String(groupName)
-r-x   removeMemberFromGroup                        Void : String(groupName),String(memberUserOrGroupName)
-r-x   removeUser                                   Void : String(userName)
-r-x   resetUserPassword                            Void : String(userName),String(newPassword)
-r-x   setGroupDescription                          Void : String(groupName),String(description)
-r-x   setUserAttributeValue                        Void : String(userName),String(userAttributeName),Object(newValue)
-r-x   setUserDescription                           Void : String(userName),String(description)
-r-x   unSet                                        Void : String(propertyName)
-r-x   userExists                                   Boolean : String(userName)
-r-x   wls_getDisplayName                           String : 
```

## 2. 编写脚本并设置定时任务

1. 在 wlst.sh 所在目录添加脚本 change_weblogic_password.py

```python
import random
import string
import subprocess
import os

def get_weblogic_current_password():
    with open("./weblogic_password_change_logs","r") as fs:
        current_password = fs.readlines()[-1]
        print("current_password: " + current_password)
        return current_password

def generate_password(length):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for i in range(length))
    return password

current_password = get_weblogic_current_password()
new_password = generate_password(12)

with open("./weblogic_password_change_logs","a") as fs:
    fs.write(new_password + '\n')

wlst_script_comment = '''
connect('weblogic', %s, 't3://localhost:7001')
cd('/SecurityConfiguration/base_domain/Realms/myrealm/AuthenticationProviders/DefaultAuthenticator')
cmo.resetUserPassword('weblogic', %s)
disconnect()
exit()
''' % (current_password,new_password)

with open("./wlst_script_comment_temp","w") as fs:
    fs.write(wlst_script_comment)

# 命令和参数
command = './wlst.sh'
args = './wlst_script_comment_temp'

# 完整命令列表
cmd = [command, args]

# 启动进程
process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

# 等待命令执行完成并获取输出
output, errors = process.communicate()

# 检查命令是否成功执行
if process.returncode == 0:
    print("Command executed successfully!")
else:
    print("Error executing command")

# 删除临时文件
if os.path.exists(args):
    os.remove(args)
    print("Del " + args + "successfully!")
```

2. 设置定时任务,每两个月执行一次
   
```shell
0 0 1 */2 * /usr/bin/python /path/to/your/change_weblogic_password.py
```