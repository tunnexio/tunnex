import copy
import unittest
import runtime_restore_runner as runner

def entry(profile, contract, namespace='net:[1]'):
    n = 1 if contract == 4 else 2
    tunnels = [{'TunnelID': str(i), 'Slot': i+1, 'Name': 'x'+str(i), 'Alias': 'owned'+str(i), 'XFRMID': i+1, 'Selected': contract != 3 and i == 0} for i in range(n)]
    engines = [{'ProfileID': profile, 'BGP': contract == 3, 'TunnelID': str(i), 'SecretRevision': 1, 'Binding': {'DesiredRevision': 2, 'ConfigurationRevision': 1}} for i in range(n)]
    observed = [{'Namespace': namespace, 'InterfaceName': 'x'+str(i), 'InterfaceIndex': 7+i, 'XFRMID': i+1} for i in range(n)]
    if n == 1:
        tunnels.append({}); engines.append({}); observed.append({})
    return {'DeliveryID': 'delivery', 'ContractVersion': contract, 'Phase': 'applied', 'Allocation': {'ProfileID': profile, 'BGP': contract == 3, 'Namespace': namespace, 'Generation': namespace, 'Tunnels': tunnels}, 'Engines': engines, 'Observed': observed, 'BGP': {'local_asn': 64512} if contract == 3 else None, 'Recovery': {'Stage': 'completed', 'SelectedSlot': 1, 'Sequence': 1} if contract == 2 else None}

class ProfileAcceptanceTests(unittest.TestCase):
    def test_classic_and_ha_active_obligation(self):
        for profile, contract in [('gcp-classic-static-ipv4-v1',4),('gcp-ha-bgp-ipv4-v1',3)]:
            before = entry(profile,contract)
            self.assertEqual(runner.active_entry({'Payload':{'Entries':[before]}}),before)
            after = entry(profile,contract,'net:[2]');after['Restoration']={'Epoch':1}
            self.assertTrue(runner.restored(before,after,'net:[2]'))
            for mutate in [lambda e:e.update(ContractVersion=2),lambda e:e['Allocation'].update(ProfileID='foreign'),lambda e:e['Observed'][0].update(Namespace='net:[9]'),lambda e:e['Observed'][0].update(InterfaceIndex=0),lambda e:e['Observed'][0].update(InterfaceName='foreign')]:
                bad=copy.deepcopy(after);mutate(bad);self.assertFalse(runner.restored(before,bad,'net:[2]'))
    def test_scope_and_immutable_binding_refusals(self):
        for profile, contract in [('gcp-classic-static-ipv4-v1',4), ('gcp-ha-bgp-ipv4-v1',3)]:
            before=entry(profile,contract)
            after=entry(profile,contract,'net:[2]');after['Restoration']={'Epoch':1}
            for mutate in [lambda e:e.update(AbsenceOnly=True),lambda e:e.update(ResetCleanup={'Namespace':'net:[2]'}),lambda e:e['Engines'][0]['Binding'].update(DesiredRevision=3),lambda e:e['Engines'][0].update(RemoteAddress='192.0.2.99')]:
                bad=copy.deepcopy(after);mutate(bad);self.assertFalse(runner.restored(before,bad,'net:[2]'))
            after['Engines'][0]['LocalAddress']='192.0.2.1'
            self.assertTrue(runner.restored(before,after,'net:[2]'), 'current underlay change is validated by controller')
            bad=copy.deepcopy(before);bad['Allocation']['Tunnels'].append({})
            with self.assertRaises(ValueError):runner.active_entry({'Payload':{'Entries':[bad]}})

    def test_classic_inactive_zero_and_actual_session(self):
        e=entry('gcp-classic-static-ipv4-v1',4)
        text='tnx-ipsec-0-d2-c1-s1: #1, ESTABLISHED\n  tnx-ipsec-0-d2-c1-s1: #1, INSTALLED'
        self.assertTrue(runner.tunnels_installed(text,e))
        links=[{'ifname':'x0','ifindex':7,'ifalias':'owned0','linkinfo':{'info_kind':'xfrm','info_data':{'if_id':1}}}]
        self.assertTrue(runner.links_owned(links,e))
        for key in ('Engines','Observed'):
            bad=copy.deepcopy(e);bad[key][1]=copy.deepcopy(bad[key][0])
            with self.assertRaises(ValueError):runner.active_entry({'Payload':{'Entries':[bad]}})
        bad=copy.deepcopy(e);bad['Allocation']['Tunnels'][1]=copy.deepcopy(bad['Allocation']['Tunnels'][0])
        with self.assertRaises(ValueError):runner.active_entry({'Payload':{'Entries':[bad]}})
        for key in ('Engines','Observed'):
            bad=copy.deepcopy(e);bad[key]=bad[key][:1]
            with self.assertRaises(ValueError):runner.active_entry({'Payload':{'Entries':[bad]}})
if __name__ == '__main__':unittest.main()
