import ansiblelint.rules

class AllHostsRule(ansiblelint.rules.AnsibleLintRule):
    id = 'Host-set-to-all'
    shortdesc = 'Dont use "all" for Hosts'
    description = 'We should not be using All in hosts.'
    severity = 'MEDIUM'
    tags = ['inventory']

    def match(self, line):
        return 'hosts: all' in line