from sigma.pipelines.common import logsource_windows, windows_logsource_mapping
from sigma.processing.conditions import IncludeFieldCondition, MatchStringCondition, LogsourceCondition, RuleProcessingItemAppliedCondition, RuleProcessingCondition
from sigma.pipelines.base import Pipeline
from sigma.processing.transformations import AddConditionTransformation, FieldMappingTransformation, DetectionItemFailureTransformation, RuleFailureTransformation, SetStateTransformation
from sigma.processing.postprocessing import EmbedQueryTransformation
from sigma.processing.conditions import LogsourceCondition, IncludeFieldCondition, ExcludeFieldCondition, RuleProcessingItemAppliedCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline, QueryPostprocessingItem
from sigma.processing.transformations import ChangeLogsourceTransformation, RuleFailureTransformation, DetectionItemFailureTransformation, FieldMappingTransformation
from sigma.rule import SigmaRule
from sigma.pipelines.common import logsource_windows_process_creation

# TODO: the following code is just an example extend/adapt as required.
# See https://sigmahq-pysigma.readthedocs.io/en/latest/Processing_Pipelines.html for further documentation.

class AggregateRuleProcessingCondition(RuleProcessingCondition):
    """"""
    def match(self, pipeline : "sigma.processing.pipeline.ProcessingPipeline", rule : SigmaRule) -> bool:
        """Match condition on Sigma rule."""
        agg_function_strings = ["| count", "| min", "| max", "| avg", "| sum", "| near"]
        condition_string = " ".join([item.lower() for item in rule.detection.condition])
        if any(f in condition_string for f in agg_function_strings):
            return True
        else:
            return False

@Pipeline
def chronicle_pipeline() -> ProcessingPipeline:        # Processing pipelines should be defined as functions that return a ProcessingPipeline object.
    return ProcessingPipeline(
        name="Generic Log Sources to Rapid7 InsightIDR Transformation",
        priority=10,
        items=[
            # Process Creation field mapping
            ProcessingItem(
                identifier="insight_idr_process_creation_fieldmapping",
                transformation=FieldMappingTransformation({
                    "ProcessId": "principal.process.pid",
                    "Image": "principal.process.file.full_path",
                    "FileVersion": "metadata.description",
                    "CurrentDirectory": "principal.file.full_path",
                    "Description": "metadata.description",
                    "description": "metadata.description",
                    "Product": "metadata.product_name",
                    "Company": "metadata.description",
                    "OriginalFileName": "src.file.full_path",
                    "CommandLine": "principal.process.command_line",
                    "User": "src.user.user_display_name",
                    "ParentProcessId": "principal.process.pid",
                    "ParentImage": "src.process.file.full_path",
                    "ParentCommandLine": "src.process.command_line",
                    "ParentUser": "src.user.userid",
                    "md5": "principal.process.file.md5",
                    "sha1": "principal.process.file.sha1",
                    "sha256": "principal.process.file.sha256"
                }),
                rule_conditions=[
                    logsource_windows_process_creation(),
                ]
            ),
            ProcessingItem(
                identifier="insight_idr_fail_process_start_fields",
                transformation=DetectionItemFailureTransformation("The InsightIDR backend does not support the IntegrityLevel, LogonId or imphash fields for process start rules."),
                rule_conditions=[
                    logsource_windows_process_creation()
                ],
                field_name_conditions=[
                    IncludeFieldCondition(
                        fields=[
                            "IntegrityLevel",
                            "imphash",
                            "Imphash",
                            "LogonId"
                        ]
                    )
                ]
            ),
            # Handle unsupported Process Start fields
            # Handle unsupported log sources - here we are checking whether none of the log source-specific transformations
            # that were set above have applied and throwing a RuleFailureTransformation error if this condition is met. Otherwise,
            # a separate processing item would be needed for every unsupported log source type
            ProcessingItem(
                identifier="insight_idr_fail_rule_not_supported",
                rule_condition_linking=any,
                transformation=RuleFailureTransformation("Rule type not yet supported by the InsightIDR Sigma backend!"),
                rule_condition_negation=True,
                rule_conditions=[
                    RuleProcessingItemAppliedCondition("insight_idr_web_proxy_logsource"),
                    RuleProcessingItemAppliedCondition("insight_idr_process_start_logsource"),
                    RuleProcessingItemAppliedCondition("insight_idr_dns_query_logsource"),
                    RuleProcessingItemAppliedCondition("insight_idr_firewall_fieldmapping"),
                    RuleProcessingItemAppliedCondition("insight_idr_ingress_authentication_logsource"),
                    RuleProcessingItemAppliedCondition("insight_idr_process_creation_fieldmapping")
                ],
            ),
            
            # Handle rules that use aggregate functions
            ProcessingItem(
                identifier="insight_idr_fail_rule_conditions_not_supported",
                transformation=RuleFailureTransformation("Rules with aggregate function conditions like count, min, max, avg, sum, and near are not supported by the InsightIDR Sigma backend!"),
                rule_conditions=[
                    AggregateRuleProcessingCondition()
                ],
            )
        ]
    )
