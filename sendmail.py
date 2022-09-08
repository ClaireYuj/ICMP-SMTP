#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
@File    :   sendmail.py
@Author  :   ClaireYuj
@Date    :   2022/9/8 10:55
------------      --------    -----------

"""
import smtplib
from email.mime.text import MIMEText
from email.header import Header

smtp_server = 'smtp.163.com'

def sendEmail(sender, password, receiver, subject, mail_msg):
    msg = MIMEText(mail_msg, 'plain', 'utf-8') # 第一个是文本内容，第二个plain是文本格式，设置为html格式，第三个utf-8是编码
    msg['From'] = sender
    msg['To'] = receiver
    msg['Subject'] = Header(subject, 'utf-8')
    try:
        smtp = smtplib.SMTP()
        smtp.connect(smtp_server)
        smtp.login(sender, password)
        smtp.sendmail(sender, receiver, msg.as_string())
        print("sucess")
    except smtplib.SMTPException as e:
        print("error" + e)
    finally:
        smtp.quit()

if  __name__ =='__main__':
    sendEmail("myemail@163.com", "password_code", "receiver@163.com", "smtp测试发送title", "smtp test msg") ## password需要是163邮箱授权的开启smtp服务的授权码


