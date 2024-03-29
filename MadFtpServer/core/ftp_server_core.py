import sys
sys.path.append('..')
import socketserver
import configparser
from conf import settings
import os,subprocess
import hashlib
import re
from core import build_user_account_db as user_db

STATUS_CODE  = {
    200 : "Task finished",
    250 : "Invalid cmd format, e.g: {'action':'get','filename':'test.py','size':344}",
    251 : "Invalid cmd ",
    252 : "Invalid auth data",
    253 : "Wrong username or password",
    254 : "Passed authentication",
    255 : "Filename doesn't provided",
    256 : "File doesn't exist on server",
    257 : "ready to send file",
    258 : "md5 verification",
    259 : "path doesn't exist on server",
    260 : "path changed",
}

import json
class FTPHandler(socketserver.BaseRequestHandler):

    def handle(self):
        while True:
            self.data = self.request.recv(1024).strip()
            print(self.client_address[0])
            print(self.data)
            if not self.data:
                print("client closed...")
                break
            data = json.loads(self.data.decode())
            if data.get('action') is not None:
                #print("---->",hasattr(self,"_auth"))
                if hasattr(self,"_%s"%data.get('action')):
                    func = getattr(self,"_%s"% data.get('action'))
                    func(data)
                else:
                    print("invalid cmd")
                    self.send_response(251)
            else:
                print("invalid cmd format")
                self.send_response(250)

    def send_response(self,status_code,data=None):
        '''向客户端返回数据'''
        response = {"status_code":status_code,
                    "status_msg":STATUS_CODE[status_code],
                    }

        if data:
            #print("goes here....")
            response.update( { 'data': data  })
        print("response::", response)
        #print("-->data to client",response)
        self.request.send(json.dumps(response).encode('utf-8'))

    def _auth(self,*args,**kwargs):
        data = args[0]
        print('_auth>data',data)
        if data.get("username") is None or data.get("password") is None:
            self.send_response(252)

        user =self.authenticate(data.get("username"),data.get("password"))
        print('user>>',user)
        # if user is None:
        #     self.send_response(253)
        # else:
        #     print("passed authentication",user)
        #     self.user = user
        #     self.user['username'] =  data.get("username")
        #
        #     self.home_dir = "%s/home/%s" %(settings.BASE_DIR,data.get("username"))
        #     self.current_dir = self.home_dir
        #     self.send_response(254)
        if user is None:
            self.send_response(253)
        else:
            print("passed authentication", user)
            self.user = user
            #文件夹名字以用户名命名
            self.home_dir = "%s/home/%s" % (settings.BASE_DIR, data.get("username"))
            self.current_dir = self.home_dir
            self.send_response(254)


    def authenticate(self,username,password):
        '''验证用户合法性，合法就返回用户数据'''

        # config = configparser.ConfigParser()
        # config.read(settings.ACCOUNT_FILE)
        # if username in config.sections():
        #     _password = config[username]["Password"]
        #     if _password == password:
        #         print("pass auth..",username)
        #         config[username]["Username"] = username
        #         return config[username]
        config = {}
        s = user_db.sql_login(username,password)
        data = s.session.query(user_db.User).filter(user_db.User.username == username).first()
        print(data)

        if username == data.username and password == data.password:
            print("pass aut h...", username)
            config['username'] = username
            config['password'] = password
            return config

    def _put(self,*args,**kwargs):
        "client send file to server"
        pass

    def _listdir(self,*args,**kwargs):
        """return file list on current dir"""
        res = self.run_cmd("ls -lsh %s" %self.current_dir)

        self.send_response(200, data=res)

    def run_cmd(self,cmd):
        #接受字符串形式的命令，返回 一个元组形式的结果，第一个元素是命令执行状态，第二个为执行结果
        cmd_res = subprocess.getstatusoutput(cmd)#运行控制台命令 ls -lsh 目标文件夹
        return cmd_res

    def _change_dir(self, *args,**kwargs):
        """change dir"""
        #print( args,kwargs)
        if args[0]:
            dest_path = "%s/%s" % (self.current_dir,args[0]['path'] )
        else:
            dest_path = self.home_dir
        #print("dest path",dest_path)

        real_path = os.path.realpath(dest_path)
        #print("read path ", real_path)
        if real_path.startswith(self.home_dir):# accessable
            if os.path.isdir(real_path):#判断目标路径是一个文件夹
                self.current_dir = real_path
                #获取当前的相对路径
                current_relative_dir = self.get_relative_path(self.current_dir)
                self.send_response(260, {'current_path':current_relative_dir})
            else:
                self.send_response(259)
        else:
            print("has no permission....to access ",real_path)
            current_relative_dir = self.get_relative_path(self.current_dir)
            self.send_response(260, {'current_path': current_relative_dir})

    def get_relative_path(self,abs_path):
        """return relative path of this user"""
        relative_path = re.sub("^%s"%settings.BASE_DIR, '', abs_path)
        # if not relative_path: #means the relative path equals to home dir
        #     relative_path = abs_path
        #
        print(("relative path",relative_path,abs_path))
        return relative_path


    def _pwd(self,*args,**kwargs):
        #res = self.run_cmd("pwd")
        current_relative_dir = self.get_relative_path(self.current_dir)
        self.send_response(200,data=current_relative_dir)

    def _get(self,*args,**kwargs):
        data = args[0]
        if data.get('filename') is None:
            self.send_response(255)
        #user_home_dir = "%s/%s" %(settings.USER_HOME,self.user["Username"])
        file_abs_path = "%s/%s" %(self.current_dir,data.get('filename'))
        print("file abs path",file_abs_path)

        if os.path.isfile(file_abs_path):
            file_obj = open(file_abs_path,"rb")
            file_size = os.path.getsize(file_abs_path)
            self.send_response(257,data={'file_size':file_size})
            self.request.recv(1) #等待客户端确认

            if data.get('md5'):
                md5_obj = hashlib.md5()
                for line in file_obj:
                    self.request.send(line)
                    md5_obj.update(line)
                else:
                    file_obj.close()
                    data = self.request.recv(1024)
                    print(data)
                    md5_val = md5_obj.hexdigest()
                    print('md5_val',md5_val)
                    self.send_response(258,{'md5':md5_val})

                    print("send file done....1")
            else:
                for line in file_obj:
                    self.request.send(line)
                else:
                    file_obj.close()
                    print("send file done....2")
        else:
            self.send_response(256)



if __name__ == "__main__":
    HOST, PORT = "localhost", 9999
