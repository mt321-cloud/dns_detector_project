#!/usr/bin/env python3

import warnings
from datetime import datetime
from multiprocessing import Lock
from .features import *


class FeatureExtractor(object):
    def __init__(self, floating_point_unit: str):
        warnings.filterwarnings("ignore")
        self.floating_point_unit = floating_point_unit
        self.__features = [
                Duration(),
                PacketsNumbers(),
                ReceivingPacketsNumbers(),
                SendingPacketsNumbers(),
                HandshakeDuration(),
                DeltaStart(),
                TotalBytes(),
                ReceivingBytes(),
                SendingBytes(),
                PacketsRate(),
                ReceivingPacketsRate(),
                SendingPacketsRate(),
                PacketsLenRate(),
                ReceivingPacketsLenRate(),
                SendingPacketsLenRate(),
                PacketsLenMin(),
                PacketsLenMax(),
                PacketsLenMean(),
                PacketsLenMedian(),
                PacketsLenMode(),
                PacketsLenStandardDeviation(),
                PacketsLenVariance(),
                PacketsLenCoefficientOfVariation(),
                PacketsLenSkewness(),
                ReceivingPacketsLenMin(),
                ReceivingPacketsLenMax(),
                ReceivingPacketsLenMean(),
                ReceivingPacketsLenMedian(),
                ReceivingPacketsLenMode(),
                ReceivingPacketsLenStandardDeviation(),
                ReceivingPacketsLenVariance(),
                ReceivingPacketsLenCoefficientOfVariation(),
                ReceivingPacketsLenSkewness(),
                SendingPacketsLenMin(),
                SendingPacketsLenMax(),
                SendingPacketsLenMean(),
                SendingPacketsLenMedian(),
                SendingPacketsLenMode(),
                SendingPacketsLenStandardDeviation(),
                SendingPacketsLenVariance(),
                SendingPacketsLenCoefficientOfVariation(),
                SendingPacketsLenSkewness(),
                ReceivingPacketsDeltaLenMin(),
                ReceivingPacketsDeltaLenMax(),
                ReceivingPacketsDeltaLenMean(),
                ReceivingPacketsDeltaLenMedian(),
                ReceivingPacketsDeltaLenStandardDeviation(),
                ReceivingPacketsDeltaLenVariance(),
                ReceivingPacketsDeltaLenMode(),
                ReceivingPacketsDeltaLenCoefficientOfVariation(),
                ReceivingPacketsDeltaLenSkewness(),
                SendingPacketsDeltaLenMin(),
                SendingPacketsDeltaLenMax(),
                SendingPacketsDeltaLenMean(),
                SendingPacketsDeltaLenMedian(),
                SendingPacketsDeltaLenStandardDeviation(),
                SendingPacketsDeltaLenVariance(),
                SendingPacketsDeltaLenMode(),
                SendingPacketsDeltaLenCoefficientOfVariation(),
                SendingPacketsDeltaLenSkewness(),
                ReceivingPacketsDeltaTimeMax(),
                ReceivingPacketsDeltaTimeMean(),
                ReceivingPacketsDeltaTimeMedian(),
                ReceivingPacketsDeltaTimeStandardDeviation(),
                ReceivingPacketsDeltaTimeVariance(),
                ReceivingPacketsDeltaTimeMode(),
                ReceivingPacketsDeltaTimeCoefficientOfVariation(),
                ReceivingPacketsDeltaTimeSkewness(),
                SendingPacketsDeltaTimeMin(),
                SendingPacketsDeltaTimeMax(),
                SendingPacketsDeltaTimeMean(),
                SendingPacketsDeltaTimeMedian(),
                SendingPacketsDeltaTimeStandardDeviation(),
                SendingPacketsDeltaTimeVariance(),
                SendingPacketsDeltaTimeMode(),
                SendingPacketsDeltaTimeCoefficientOfVariation(),
                SendingPacketsDeltaTimeSkewness(),
            ]
        self.__dns_features = [
                DomainName(),
                WhoisDomainName(),
                TopLevelDomain(),
                SecondLevelDomain(),
                DomainNameLen(),
                SubDomainNameLen(),
                UniGramDomainName(),
                BiGramDomainName(),
                TriGramDomainName(),
                NumericalPercentage(),
                CharacterDistribution(),
                DomainEmail(),
                DomainRegistrar(),
                DomainCreationDate(),
                DomainExpirationDate(),
                DomainAge(),
                DomainCountry(),
                DomainDNSSEC(),
                DomainOrganization(),
                DomainAddress(),
                DomainCity(),
                DomainState(),
                DomainZipcode(),
                DomainNameServers(),
                DomainUpdatedDate(),
                CharacterEntropy(),
                ContinuousNumericMaxLen(),
                ContinuousAlphabetMaxLen(),
                ContinuousConsonantsMaxLen(),
                ContinuousSameAlphabetMaxLen(),
                VowelsConsonantRatio(),
                ConvFreqVowelsConsonants(),
                DistinctTTLValues(),
                TTLValuesMin(),
                TTLValuesMax(),
                TTLValuesMean(),
                TTLValuesMode(),
                TTLValuesVariance(),
                TTLValuesStandardDeviation(),
                TTLValuesMedian(),
                TTLValuesSkewness(),
                TTLValuesCoefficientOfVariation(),
                DistinctARecords(),
                DistinctNSRecords(),
                AvgAuthorityResourceRecords(),
                AvgAdditionalResourceRecords(),
                AvgAnswerResourceRecords(),
                QueryResourceRecordType(),
                AnsResourceRecordType(),
                QueryResourceRecordClass(),
                AnsResourceRecordClass(),
            ]
        self.__features = self.__features + self.__dns_features

    def execute(self, data: list, data_lock, flows: list, features_ignore_list: list = [],
            label: str = "", features_allow_list: list = []) -> list:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            extracted_data = []
            allowed_features = set(features_allow_list) if len(features_allow_list) > 0 else None

            def is_allowed(feature_name: str) -> bool:
                if allowed_features is None:
                    return True
                return feature_name in allowed_features

            for flow in flows:
                features_of_flow = {}
                if is_allowed("flow_id"):
                    features_of_flow["flow_id"] = str(flow)
                if is_allowed("timestamp"):
                    features_of_flow["timestamp"] = datetime.fromtimestamp(flow.get_timestamp())
                if is_allowed("src_ip"):
                    features_of_flow["src_ip"] = flow.get_src_ip()
                if is_allowed("src_port"):
                    features_of_flow["src_port"] = flow.get_src_port()
                if is_allowed("dst_ip"):
                    features_of_flow["dst_ip"] = flow.get_dst_ip()
                if is_allowed("dst_port"):
                    features_of_flow["dst_port"] = flow.get_dst_port()
                if is_allowed("protocol"):
                    features_of_flow["protocol"] = flow.get_protocol()
                for feature in self.__features:
                    if not is_allowed(feature.name):
                        continue
                    if feature.name in features_ignore_list:
                        continue
                    feature.set_floating_point_unit(self.floating_point_unit)
                    try:
                        features_of_flow[feature.name] = feature.extract(flow)
                    except Exception as e:
                        print(f">> Error occurred in feature extraction for extracting >> {feature.name} << for the flow with {str(flow)} id.\n{e}\n")
                        pass
                if is_allowed("label"):
                    features_of_flow["label"] = label
                extracted_data.append(features_of_flow)
            with data_lock:
                data.extend(extracted_data)
                del extracted_data