"""
.. module: lemur.elbs.models
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>

"""
from sqlalchemy import Column, Integer, BigInteger, String, ForeignKey, DateTime, PassiveDefault, func

from lemur.database import db
from lemur.certificates import service as cert_service
from lemur.certificates.models import Certificate, get_name_from_arn


class Listener(db.Model):
    __tablename__ = 'listeners'
    id = Column(BigInteger, primary_key=True)
    certificate_id = Column(Integer, ForeignKey(Certificate.id), index=True)
    elb_id = Column(BigInteger, ForeignKey("elbs.id"), index=True)
    instance_port = Column(Integer)
    instance_protocol = Column(String(16))
    load_balancer_port = Column(Integer)
    load_balancer_protocol = Column(String(16))
    date_created = Column(DateTime, PassiveDefault(func.now()), nullable=False)

    def __init__(self, listener):
        self.load_balancer_port = listener.load_balancer_port
        self.load_balancer_protocol = listener.protocol
        self.instance_port = listener.instance_port
        self.instance_protocol = listener.instance_protocol
        if listener.ssl_certificate_id not in ["Invalid-Certificate", None]:
            self.certificate_id = cert_service.get_by_name(get_name_from_arn(listener.ssl_certificate_id)).id

    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

    def serialize(self):
        blob = self.as_dict()
        del blob['date_created']
        return blob
