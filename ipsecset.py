#coding:utf-8
"""
添加规则到ipsec
因为salt中返回的结果不支持中文，而筛选器列表名称有中文，所以匹配的是所有的规则列表
has()方法跳过了筛选器列表的判断:
if k==u'filterlist':
    continue
"""
import subprocess
import traceback
import ipsecget
import cStringIO
import sys
import time
import itertools

#系统中存在的filters
__filters=[]

def check_num(func):
    """装饰器
    检查传入的数字参数格式是否有问题。
    """
    def t(arg):
        #right=[str(n) for n in range(10)]+[',','-']

        arg=arg.replace(' ','') #去掉空格

        #res=[x for x in arg if x not in right]
        #if res:
        #    raise NUMARG_ERROR('args err!1')

        res=[x for x in [',','-'] if arg.startswith(x) or arg.endswith(x)]
        if res:
            print 'args err!2'
            raise NUMARG_ERROR('args err!2')

        err_arg=[',-','-,','--',',,']
        res=[x for x in err_arg if x in arg]
        if res:
            raise NUMARG_ERROR('args err!3')
        return func(arg)
    return t


class NUMARG_ERROR(Exception):
    def __init__(self,value):
        self.value=value

    def __str__(self):
        return self.value

def init(func):
    """装饰器
    初始化，读取ipsec规则
    """
    def t(*args,**kwargs):
        global __filters
        __filters=ipsecget.get_filters()
        #open('d:\\backup\\ipsecset.log','a').write(str(__filters))
        return func(*args,**kwargs)
    return  t

def catch_exception(func):
    """装饰器
    捕获异常"""
    def t(*args,**kwargs):
        try:
            return func(*args,**kwargs)
        except NUMARG_ERROR,e:
            return e.__str__()
        except:#打印所有未知异常
            err_fp = cStringIO.StringIO() #创建内存文件对象
            traceback.print_exc(file=err_fp)
            err_msg = err_fp.getvalue()
            err_msg='\r\n'.join(err_msg.split( '\n'))
            #self.response.out.write(err_msg)
            return  err_msg
    return t


def add_filter(d):
    """将字典类型的规则转换为命令
    netsh ipsec static add filter
    filterlist=基础规则 vdisk srcaddr=Me dstaddr=any dstport=4450 protocol=TCP"""
    #筛选器列表需要手动指定
    cmd=u'netsh ipsec static add filter '
    for k, v in d.iteritems():
        cmd += u'%s=%s '%(k,v)
    if has(d):
        return u'rule already exist,srcaddr:%s srcport:%s dstaddr:%s dstport:%s'%(d['srcaddr'],d['srcport'],d['dstaddr'],d['dstport'])
    __filters.append(d)
    output=subprocess.Popen(cmd.encode('cp936'),shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout.read()
    return output.decode('cp936')
    #print output.stdout.read().decode('cp936')

def has(d):
    """filter是否已存在"""
    for filter in __filters:
        has=True
        for k,v in filter.iteritems():
            if k ==u'description':
                continue
            if k==u'filterlist':#因为在salt中不支持中文，而filterlist有包含中文，为避免出错，暂时忽略掉filterlist了。
                continue
            if k==u'filterlist':#filterlist不用变为小写
                if d[k]!=v:
                    has=False
                    break;
            elif d[k]!=v.lower():
                has=False
                break;
        if has:
            return True
    return False

@check_num
def extend_num(arg):
    """将- ,扩展成数字列表"""
    res=[]
    if ',' in arg:
        s=arg.split(',')
        for x in s:
            if '-' in x:
                #e.g.：将21-25，切割成21和25，并转换成数字，然后用range 循环获取端口，最后将端口转换成字符串返回
                y=[ str(xx).decode('utf-8') for xx in range(int(x.split('-')[0].strip()),int(x.split('-')[1].strip())+1)]
                res.extend(y)
            else:
                res.append(x.strip())
    elif '-' in arg:#这里说明只有一个区间,如果有多个区间的话，使用逗号隔开，就会满足上个if条件
        x=arg   #与上面的列表推导参数保持一致
        y=[ str(xx).decode('utf-8') for xx in range(int(x.split('-')[0].strip()),int(x.split('-')[1].strip())+1)]
        res.extend(y)
    else:
        res.append(arg.strip())
    res=dict.fromkeys(res).keys()    #过滤掉重复的值
    res.sort()
    return res

def analyze_cmd(args):
    """分析传入命令行格式的参数
    必须有的参数：srcaddr，dstaddr，dstport
    e.q.:srcaddr=10.1.1.1 dstaddr=10.1.1.2 dstport=8080"""
    #args=args.split(' ')
    d=dict([x.strip().split('=') for x in args if x.strip()])
    return analyze_dict(d)

def analyze_dict(d_info):
    """1,分析传入的数据，如“，”，“-”等批量操作符
    2,过滤掉已存在的filter"""

    #d={
    #    u'srcaddr' : u'192.168.1.1-2' ,
    #    u'srcport' : u'1001' ,
    #    u'dstport' : u'21',
    #    u'dstaddr' : u'10.1.11.101',
    #    u'dstmask' : u'255.255.255.255' ,
    #    u'protocol' : u'TCP' ,
    #    u'description' : u'\"haha\"' ,
    #    u'mirrored' : u'YES' ,
    #    u'filterlist' : u'\"ip筛选器列表2\"' ,
    #    u'srcmask' : u'255.255.255.255' ,
    #}

    try:
        d_info=dict([(str(k).decode('utf-8'),str(v).decode('utf-8')) for (k,v) in d_info.iteritems()])
    except:
        pass
        #print 'WARNING:decode utf-8 fail.'
    try:
        d_info=dict([(str(k).decode('cp936'),str(v).decode('cp936')) for (k,v) in d_info.iteritems()])
    except:
        pass
        #print 'WARNING:decode cp936 fail.It may be Unicode or other coding.'

    #将键，值都变成小写，便于后面对比
    #filterlist的值不用变成小写
    #步骤：先将所有键名变为小写，然后查看是否有filterlist键名，如果有，保存到临时变量里，待所有键值都变为小写后，在用临时变量恢复。
    d_info=dict([(k.lower(),v) for k,v in d_info.iteritems()])
    if d_info.has_key('filterlist'):
        filterlist=d_info['filterlist']
    d_info=dict([(k,v.lower()) for k,v in d_info.iteritems()])
    if d_info.has_key('filterlist'):
        d_info['filterlist']=filterlist

    #参数是否足够
    if not d_info.has_key(u'srcaddr') or not d_info.has_key(u'dstaddr') or not d_info.has_key(u'dstport'):
        raise NUMARG_ERROR(u'analyze_cmd():args not enouth!')
    now=time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
    d={
        u'srcport' : u'0' ,
        u'srcmask' : u'255.255.255.255',
        u'dstmask' : u'255.255.255.255' ,
        u'protocol' : u'tcp' ,
        u'mirrored' : u'yes',
        u'filterlist' : u'\"选用规则\"' ,
        u'description' : u'\"add by script %s\"'%(now) ,
        }
    d.update(d_info)

    #如果源或目的ip是any，需要修改相应的掩码为0.0.0.0
    if d['srcaddr']==u'any':
        d[u'srcmask']=u'0.0.0.0'
    if d['dstaddr']==u'any':
        d[u'dstmask']=u'0.0.0.0'


    #将描述和filter名称用双引号括起来
    if not d[u'filterlist'].startswith('"') or not d[u'filterlist'].endswith('"'):
        d[u'filterlist']='\"%s\"'%(d[u'filterlist'])
    if not d[u'description'].startswith('"') or not d[u'description'].endswith('"'):
        d[u'description']='\"%s\"'%(d[u'description'])

    #扩展数字
    srcports=extend_num(d[u'srcport'])
    dstports=extend_num(d[u'dstport'])
    if '.' in d[u'srcaddr']:
        srcaddr_seq=d[u'srcaddr'].split('.')
        srcaddrs=[ '.'.join(srcaddr_seq[0:3])+'.%s'%(x) for x in  extend_num(srcaddr_seq[3])]
    else:
        srcaddrs=[d[u'srcaddr'].strip()]
    if '.' in d[u'dstaddr']:
        dstaddr_seq=d[u'dstaddr'].split('.')
        dstaddrs=[ '.'.join(dstaddr_seq[0:3])+'.%s'%(x) for x in  extend_num(dstaddr_seq[3])]
    else:
        dstaddrs=[d[u'dstaddr'].strip()]

    #print 'srcaddrs',srcaddrs
    #print 'dstaddrs',dstaddrs
    #print 'srcports',srcports
    #print 'dstports',dstports

    filter_dicts=[]
    for srcport,dstport,srcaddr,dstaddr in itertools.product(srcports,dstports,srcaddrs,dstaddrs):
        tmp_d=d.copy()
        tmp_d[u'srcport']=srcport
        tmp_d[u'dstport']=dstport
        tmp_d[u'srcaddr']=srcaddr
        tmp_d[u'dstaddr']=dstaddr
        filter_dicts.append(tmp_d)
    return filter_dicts


@catch_exception
@init
def insert(args):
    """主要接口，接收传入的insert参数
    args:{'srcaddr':'1.1.1.1','dstaddr':'2.2.2.2','dstport':'90'}"""
    #raise Exception(str(args)+'\r\n'+str(sys.argv))
    l=[]
    if args:
        l=analyze_dict(args)
    elif len(sys.argv)>1:
        args=sys.argv[1:]
        l=analyze_cmd(args)
    else:
        print 'args is empty'
    output=''
    for filter in l:
        res=add_filter(filter)
        output+=res.strip()+'\r\n'
    return output

if __name__ == '__main__':
    #res=insert({'srcaddr':'1.1.1.1','dstaddr':'2.2.2.2','dstport':'90'})
    res=insert({})
    print res
