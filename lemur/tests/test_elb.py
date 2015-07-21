# import boto
# from lemur.tests import LemurTestCase

# from moto import mock_elb, mock_sts


# class ELBTestCase(LemurTestCase):
#    @mock_sts
#    @mock_elb
#    def test_add_listener(self):
#        from lemur.common.services.aws.elb import create_new_listeners
#        conn = boto.connect_elb()
#        zones = ['us-east-1a', 'us-east-1b']
#        ports = [(80, 8080, 'http')]
#        conn.create_load_balancer('my-lb', zones, ports)
#        create_new_listeners('111', 'us-east-1', 'my-lb', listeners=[('443', '80', 'HTTP')])
#        balancer = conn.get_all_load_balancers()[0]
#        self.assertEqual(balancer.name, "my-lb")
#        self.assertEqual(len(balancer.listeners), 2)
#
#    @mock_sts
#    @mock_elb
#    def test_update_listener(self):
#        from lemur.common.services.aws.elb import update_listeners
#        conn = boto.connect_elb()
#        zones = ['us-east-1a', 'us-east-1b']
#        ports = [(80, 8080, 'http')]
#        conn.create_load_balancer('my-lb', zones, ports)
#        update_listeners('111', 'us-east-1', 'my-lb', listeners=[('80', '7001', 'http')])
#        balancer = conn.get_all_load_balancers()[0]
#        listener = balancer.listeners[0]
#        self.assertEqual(listener.load_balancer_port, 80)
#        self.assertEqual(listener.instance_port, 7001)
#        self.assertEqual(listener.protocol, "HTTP")
#
#    @mock_sts
#    @mock_elb
#    def test_set_certificate(self):
#        from lemur.common.services.aws.elb import attach_certificate
#        conn = boto.connect_elb()
#        zones = ['us-east-1a', 'us-east-1b']
#        ports = [(443, 7001, 'https', 'sslcert')]
#        conn.create_load_balancer('my-lb', zones, ports)
#        attach_certificate('1111', 'us-east-1', 'my-lb', 443, 'somecert')
#        balancer = conn.get_all_load_balancers()[0]
#        listener = balancer.listeners[0]
#        self.assertEqual(listener.load_balancer_port, 443)
#        self.assertEqual(listener.instance_port, 7001)
#        self.assertEqual(listener.protocol, "HTTPS")
#        self.assertEqual(listener.ssl_certificate_id, 'somecert')
#
