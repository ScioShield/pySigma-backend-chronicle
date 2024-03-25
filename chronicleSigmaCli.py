from sigma.pipelines.chronicle.chronicle import chronicle_pipeline
import sigma.collection
from sigma.backends.chronicle.chronicle_yaral import chronicleBackendYaral
import sigma.modifiers
import glob 

pipeline = chronicle_pipeline()
backend = chronicleBackendYaral(pipeline)
#
#process_start_rules = [r"proc_creation_win_7zip_exfil_dmp_files.yml",
#                       r"sysmon_regsvr32_network_activity.yml"]
process_start_rules = glob.glob("rules/*.yml")
#process_start_rules = [r"rules/proc_creation_win_susp_obfuscated_ip_download.yml"]

process_start_rule_collection = sigma.collection.SigmaCollection.load_ruleset(process_start_rules)

# convert the rules
successful_conversions = 0
failed_conversions = 0

for rule in process_start_rule_collection.rules:
    try:
        print(rule.title + " conversion:")
        print(backend.convert_rule(rule, "default")[0])
        print("\n")
        successful_conversions += 1
    except Exception as e:
        print(f"Failed to convert rule: {rule.title}")
        print(f"Error: {str(e)}\n")
        failed_conversions += 1

print(f"Successful conversions: {successful_conversions}")
print(f"Failed conversions: {failed_conversions}")