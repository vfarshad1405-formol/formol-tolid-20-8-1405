import json
import re
import unittest
from sqlalchemy import select
import app as cloud


def login(client, username, password):
    r=client.get('/login')
    match=re.search(rb'name="nonce" value="([^"]+)"',r.data)
    assert match, r.status_code
    return client.post('/login',data={'nonce':match.group(1).decode(),'username':username,'password':password})

class CloudTests(unittest.TestCase):
    def test_full_security_and_concurrency(self):
        server=cloud.app; server.config['TESTING']=True
        a=server.test_client();b=server.test_client();anonymous=server.test_client()
        self.assertEqual(anonymous.get('/api/data').status_code,401)
        self.assertEqual(anonymous.post('/login',data={'username':'demo','password':'Primary-Test-Password1'}).status_code,403)
        self.assertEqual(login(a,'demo','Primary-Test-Password1').status_code,302)
        a_info=a.get('/api/session').get_json(); acsrf=a_info['csrf']
        self.assertEqual(a.post('/api/users',json={'username':'colleague','password':'Colleague-Test-Pass1'}).status_code,403)
        self.assertEqual(a.post('/api/users',json={'username':'colleague','password':'Colleague-Test-Pass1'},headers={'X-Afraz-Token':acsrf}).status_code,201)
        self.assertEqual(login(b,'colleague','Colleague-Test-Pass1').status_code,302)
        bcsrf=b.get('/api/session').get_json()['csrf']
        ar=a.get('/api/data');br=b.get('/api/data');revision=ar.headers['X-Revision']
        self.assertEqual(revision,br.headers['X-Revision'])
        ad=ar.get_json();bd=br.get_json(); ad['products'][0]['name']='ویرایش اول'; ad['audit']=[{'date':'2026-01-01','description':'test'}]
        saved=a.post('/api/data',json=ad,headers={'X-Afraz-Token':acsrf,'X-Revision':revision})
        self.assertEqual(saved.status_code,200);self.assertEqual(int(saved.headers['X-Revision']),int(revision)+1)
        bd['products'][0]['name']='ویرایش قدیمی'
        self.assertEqual(b.post('/api/data',json=bd,headers={'X-Afraz-Token':bcsrf,'X-Revision':revision}).status_code,409)
        fresh=b.get('/api/data');self.assertEqual(fresh.get_json()['products'][0]['name'],'ویرایش اول');self.assertEqual(fresh.get_json()['audit'][0]['actor'],'demo')
        invalid=fresh.get_json();invalid['recipes'][0]['components'][0]['resourceId']=[]
        self.assertEqual(b.post('/api/data',json=invalid,headers={'X-Afraz-Token':bcsrf,'X-Revision':fresh.headers['X-Revision']}).status_code,400)
        with cloud.engine.connect() as c:
            hashes=c.execute(select(cloud.users.c.password_hash)).scalars().all()
        self.assertTrue(all('Test-Password' not in x and x.startswith('scrypt$') for x in hashes))
        # Changing password retains current session, revokes other sessions for that account.
        b2=server.test_client();self.assertEqual(login(b2,'colleague','Colleague-Test-Pass1').status_code,302)
        r=b.post('/api/password',json={'currentPassword':'Colleague-Test-Pass1','newPassword':'A-New-Strong-Pass99'},headers={'X-Afraz-Token':bcsrf})
        self.assertEqual(r.status_code,200);self.assertEqual(b2.get('/api/session').status_code,401)
        users=a.get('/api/users').get_json()['users'];other=next(x for x in users if x['username']=='colleague')
        self.assertEqual(a.delete('/api/users/'+str(other['id']),headers={'X-Afraz-Token':acsrf}).status_code,200)
        self.assertEqual(b.get('/api/session').status_code,401)
        self.assertEqual(a.delete('/api/users/'+str(a_info['userId']),headers={'X-Afraz-Token':acsrf}).status_code,400)
        self.assertEqual(a.post('/api/logout',headers={'X-Afraz-Token':acsrf}).status_code,200);self.assertEqual(a.get('/api/session').status_code,401)

    def test_race_on_same_revision(self):
        from concurrent.futures import ThreadPoolExecutor
        a=cloud.app.test_client(); b=cloud.app.test_client()
        self.assertEqual(login(a,'demo','Primary-Test-Password1').status_code,302)
        self.assertEqual(login(b,'demo','Primary-Test-Password1').status_code,302)
        ca=a.get('/api/session').get_json()['csrf']; cb=b.get('/api/session').get_json()['csrf']
        ar=a.get('/api/data');br=b.get('/api/data');self.assertEqual(ar.headers['X-Revision'],br.headers['X-Revision'])
        da=ar.get_json();db=br.get_json();da['settings']['company']='winner A';db['settings']['company']='winner B'
        def commit(args):
            client,csrf,data,rev=args
            return client.post('/api/data',json=data,headers={'X-Afraz-Token':csrf,'X-Revision':rev}).status_code
        with ThreadPoolExecutor(max_workers=2) as pool:
            statuses=list(pool.map(commit,[(a,ca,da,ar.headers['X-Revision']),(b,cb,db,br.headers['X-Revision'])]))
        self.assertEqual(sorted(statuses),[200,409])
        self.assertIn(a.get('/api/data').get_json()['settings']['company'],['winner A','winner B'])

    def test_z_rate_limit(self):
        c=cloud.app.test_client()
        for _ in range(8): self.assertEqual(login(c,'does-not-exist','Wrong-Password-1234').status_code,401)
        self.assertEqual(login(c,'does-not-exist','Wrong-Password-1234').status_code,429)

if __name__=='__main__': unittest.main()
