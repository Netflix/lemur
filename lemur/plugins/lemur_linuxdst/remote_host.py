#!/usr/bin/python
from lemur.certificates import service
import os
import paramiko


def copy_cert(dst_user, dst_priv, dst_priv_key, dst_host, dst_port, dst_dir, dst_file, dst_data):

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    if dst_priv_key is None:
        priv_key = paramiko.RSAKey.from_private_key_file(dst_priv)
    else:
        priv_key = paramiko.RSAKey.from_private_key_file(dst_priv, dst_priv_key)
    ssh.connect(dst_host, username=dst_user, port=dst_port, pkey=priv_key)
    sftp = ssh.open_sftp()
    try:
        sftp.mkdir(dst_dir)
    except IOError:
        pass
    cert_out = sftp.open(dst_dir + '/' + filename, 'w')
    cert_out.write(data)
    cert_out.close()
    ssh.close()

def create_cert(name, dst_dir, export_type, dstUser, dst_priv, dst_priv_key, dst_host, dst_host_port):

    lem_cert = service.get_by_name(name)
    dst_dir = dst_dir + '/' + lem_cert.cn
    dst_file = 'cert.pem'
    if export_type == 'NGINX':
        dst_data = lem_cert.body + '\n' + lem_cert.chain
        chin_req = False
    elif export_type == '3File':
        dst_data = lem_cert.body
        chain_req = True
    else:
        dst_data = lem_cert.body
    copy_cert(dst_user, dst_priv, dst_priv_key, dst_host, dst_host_port, dst_dir, dst_file, dst_data)
    if chain_req = True:
        dst_file = 'chain.pem'
        dst_data = lem_cert.chain_req
        copy_cert(dst_user, dst_priv, dst_priv_key, dst_host, dst_host_port, dst_dir, dst_file, dst_data)
    dst_file = 'priv.key'
    dst_data = lem_cert.private_key
    copy_cert(dst_user, dst_priv, dst_priv_key, dst_host, dst_host_port, dst_dir, dst_file, dst_data)
