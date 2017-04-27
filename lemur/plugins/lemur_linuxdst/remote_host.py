#!/usr/bin/python
from lemur.certificates import service
import paramiko
import stat


def copy_cert(cert_cn, dst_user, dst_priv, dst_priv_key, dst_host, dst_port, dst_dir, dst_file, dst_data):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # include the private key password if required
    if dst_priv_key is None:
        priv_key = paramiko.RSAKey.from_private_key_file(dst_priv)
    else:
        priv_key = paramiko.RSAKey.from_private_key_file(dst_priv, dst_priv_key)

    # open the sftp connection
    ssh.connect(dst_host, username=dst_user, port=dst_port, pkey=priv_key)
    sftp = ssh.open_sftp()

    # make the directory on the destination server
    # files will be in a a folder based on the cert_cn
    # example:
    # destination folder: /etc/nginx/certs/
    # files will go in: /etc/nginx/certs/your.cn.com/cert.pem
    try:
        sftp.mkdir(dst_dir)
    except IOError:
        pass
    try:
        dst_dir_cn = dst_dir + '/' + cert_cn
        sftp.mkdir(dst_dir_cn)
    except IOError:
        pass

    cert_out = sftp.open(dst_dir_cn + '/' + dst_file, 'w')
    cert_out.write(dst_data)
    cert_out.close()
    sftp.chmod(dst_dir_cn + '/' + dst_file, (stat.S_IRUSR))
    ssh.close()


def create_cert(name, dst_dir, export_type, dst_user, dst_priv, dst_priv_key, dst_host, dst_host_port):
    lem_cert = service.get_by_name(name)
    dst_file = 'cert.pem'
    chain_req = False

    if export_type == 'NGINX':
        # This process will result in a cert.pem file with the body and chain in a single file
        if lem_cert.chain is None:
            dst_data = lem_cert.body
        else:
            dst_data = lem_cert.body + '\n' + lem_cert.chain
        chain_req = False

    elif export_type == '3File':
        # This process will results in three files. cert.pem, priv.key, chain.pem
        dst_data = lem_cert.body
        chain_req = True

    else:
        dst_data = lem_cert.body

    copy_cert(lem_cert.cn, dst_user, dst_priv, dst_priv_key, dst_host, dst_host_port, dst_dir, dst_file, dst_data)

    if chain_req is True:
        dst_file = 'chain.pem'
        dst_data = lem_cert.chain_req
        copy_cert(lem_cert.cn, dst_user, dst_priv, dst_priv_key, dst_host, dst_host_port, dst_dir, dst_file, dst_data)

    dst_file = 'priv.key'
    dst_data = lem_cert.private_key
    copy_cert(lem_cert.cn, dst_user, dst_priv, dst_priv_key, dst_host, dst_host_port, dst_dir, dst_file, dst_data)
