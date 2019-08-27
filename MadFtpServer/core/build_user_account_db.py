import sqlalchemy
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import create_session,sessionmaker
from sqlalchemy import Column,String,engine,Integer

Base = declarative_base()
class sql_login():
    def __init__(self,username,password):
        self.username = username
        self.password = password
        self.engine = engine.create_engine(f'mysql+pymysql://{self.username}:{self.password}@localhost/testdb' ,echo=False)
        self.session = sessionmaker(bind=self.engine)()

class User(Base):
    __tablename__ = 'ftp_user_account'
    id = Column(Integer,primary_key=True,unique=True)
    username = Column(String(30),unique=True)
    password = Column(String(30))

s  = sql_login('lisi','qwerqwer')
data = s.session.query(User).filter(User.username == 'zhangxt').first()
print(data.username)

# users = {User(username='zhangxt',password='qwerqwer'),
# User(username='lisi',password='qwerqwer'),
# User(username='wangwu',password='qwerqwer'),
# User(username='laoliu',password='qwerqwer'),
#          }
#
# Base.metadata.create_all(engine)
#session.add_all(users)


