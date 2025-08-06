"""
mIRage DFIR Platform - Integration Manager
Centralized management of all threat intelligence and EDR/XDR integrations
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
import structlog

from .threat_intel.misp.connector import MISPConnector
from .threat_intel.virustotal.connector import VirusTotalConnector
from .threat_intel.anyrun.connector import AnyRunConnector
from .threat_intel.greynoise.connector import GreyNoiseConnector
from .threat_intel.hybrid_analysis.connector import HybridAnalysisConnector

from .edr_xdr.sentinelone.connector import SentinelOneConnector
from .edr_xdr.crowdstrike.connector import CrowdStrikeConnector
from .edr_xdr.sophos.connector import SophosConnector

logger = structlog.get_logger(__name__)

class IntegrationManager:
    """Centralized manager for all platform integrations"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.threat_intel_connectors = {}
        self.edr_connectors = {}
        self.connection_status = {}
        self.rate_limiters = {}
        
        # Initialize connectors
        self._initialize_threat_intel_connectors()
        self._initialize_edr_connectors()
        
        # Thread pool for concurrent operations
        self.executor = ThreadPoolExecutor(max_workers=10)
        
    def _initialize_threat_intel_connectors(self):
        """Initialize threat intelligence connectors"""
        
        # MISP
        if self.config.get('MISP_URL') and self.config.get('MISP_API_KEY'):
            try:
                misp_config = {
                    'base_url': self.config['MISP_URL'],
                    'api_key': self.config['MISP_API_KEY'],
                    'verify_ssl': self.config.get('MISP_VERIFY_SSL', True),
                    'rate_limit': self.config.get('MISP_RATE_LIMIT', 60),
                    'enabled': True
                }
                self.threat_intel_connectors['misp'] = MISPConnector(misp_config)
                logger.info("MISP connector initialized", url=self.config['MISP_URL'])
            except Exception as e:
                logger.error("Failed to initialize MISP connector", error=str(e))
        
        # VirusTotal
        if self.config.get('VIRUSTOTAL_API_KEY'):
            try:
                vt_config = {
                    'api_key': self.config['VIRUSTOTAL_API_KEY'],
                    'rate_limit': self.config.get('VIRUSTOTAL_RATE_LIMIT', 4),
                    'enabled': True
                }
                self.threat_intel_connectors['virustotal'] = VirusTotalConnector(vt_config)
                logger.info("VirusTotal connector initialized")
            except Exception as e:
                logger.error("Failed to initialize VirusTotal connector", error=str(e))
        
        # Any.Run
        if self.config.get('ANYRUN_API_KEY'):
            try:
                anyrun_config = {
                    'api_key': self.config['ANYRUN_API_KEY'],
                    'rate_limit': self.config.get('ANYRUN_RATE_LIMIT', 10),
                    'enabled': True
                }
                self.threat_intel_connectors['anyrun'] = AnyRunConnector(anyrun_config)
                logger.info("Any.Run connector initialized")
            except Exception as e:
                logger.error("Failed to initialize Any.Run connector", error=str(e))
        
        # GreyNoise
        if self.config.get('GREYNOISE_API_KEY'):
            try:
                greynoise_config = {
                    'api_key': self.config['GREYNOISE_API_KEY'],
                    'rate_limit': self.config.get('GREYNOISE_RATE_LIMIT', 100),
                    'enabled': True
                }
                self.threat_intel_connectors['greynoise'] = GreyNoiseConnector(greynoise_config)
                logger.info("GreyNoise connector initialized")
            except Exception as e:
                logger.error("Failed to initialize GreyNoise connector", error=str(e))
        
        # Hybrid Analysis
        if self.config.get('HYBRID_ANALYSIS_API_KEY'):
            try:
                hybrid_config = {
                    'api_key': self.config['HYBRID_ANALYSIS_API_KEY'],
                    'secret': self.config.get('HYBRID_ANALYSIS_SECRET'),
                    'rate_limit': self.config.get('HYBRID_ANALYSIS_RATE_LIMIT', 20),
                    'enabled': True
                }
                self.threat_intel_connectors['hybrid_analysis'] = HybridAnalysisConnector(hybrid_config)
                logger.info("Hybrid Analysis connector initialized")
            except Exception as e:
                logger.error("Failed to initialize Hybrid Analysis connector", error=str(e))
    
    def _initialize_edr_connectors(self):
        """Initialize EDR/XDR connectors"""
        
        # SentinelOne
        if self.config.get('SENTINELONE_BASE_URL') and self.config.get('SENTINELONE_API_TOKEN'):
            try:
                s1_config = {
                    'base_url': self.config['SENTINELONE_BASE_URL'],
                    'api_token': self.config['SENTINELONE_API_TOKEN'],
                    'account_id': self.config.get('SENTINELONE_ACCOUNT_ID'),
                    'enabled': True
                }
                self.edr_connectors['sentinelone'] = SentinelOneConnector(s1_config)
                logger.info("SentinelOne connector initialized", url=self.config['SENTINELONE_BASE_URL'])
            except Exception as e:
                logger.error("Failed to initialize SentinelOne connector", error=str(e))
        
        # CrowdStrike
        if self.config.get('CROWDSTRIKE_CLIENT_ID') and self.config.get('CROWDSTRIKE_CLIENT_SECRET'):
            try:
                cs_config = {
                    'client_id': self.config['CROWDSTRIKE_CLIENT_ID'],
                    'client_secret': self.config['CROWDSTRIKE_CLIENT_SECRET'],
                    'base_url': self.config.get('CROWDSTRIKE_BASE_URL', 'https://api.crowdstrike.com'),
                    'enabled': True
                }
                self.edr_connectors['crowdstrike'] = CrowdStrikeConnector(cs_config)
                logger.info("CrowdStrike connector initialized")
            except Exception as e:
                logger.error("Failed to initialize CrowdStrike connector", error=str(e))
        
        # Sophos Central
        if self.config.get('SOPHOS_CLIENT_ID') and self.config.get('SOPHOS_CLIENT_SECRET'):
            try:
                sophos_config = {
                    'client_id': self.config['SOPHOS_CLIENT_ID'],
                    'client_secret': self.config['SOPHOS_CLIENT_SECRET'],
                    'base_url': self.config.get('SOPHOS_BASE_URL'),
                    'enabled': True
                }
                self.edr_connectors['sophos'] = SophosConnector(sophos_config)
                logger.info("Sophos Central connector initialized")
            except Exception as e:
                logger.error("Failed to initialize Sophos connector", error=str(e))
    
    def get_all_status(self) -> Dict[str, Any]:
        """Get status of all integrations"""
        status = {
            'threat_intel': {},
            'edr_xdr': {},
            'summary': {
                'total_integrations': 0,
                'active_integrations': 0,
                'failed_integrations': 0
            },
            'last_checked': datetime.utcnow().isoformat()
        }
        
        # Check threat intel connectors
        for name, connector in self.threat_intel_connectors.items():
            try:
                result = connector.test_connection()
                status['threat_intel'][name] = {
                    'status': 'active' if result['success'] else 'failed',
                    'enabled': connector.enabled,
                    'last_check': datetime.utcnow().isoformat(),
                    'error': result.get('error') if not result['success'] else None
                }
                status['summary']['total_integrations'] += 1
                if result['success']:
                    status['summary']['active_integrations'] += 1
                else:
                    status['summary']['failed_integrations'] += 1
                    
            except Exception as e:
                status['threat_intel'][name] = {
                    'status': 'error',
                    'enabled': connector.enabled,
                    'last_check': datetime.utcnow().isoformat(),
                    'error': str(e)
                }
                status['summary']['total_integrations'] += 1
                status['summary']['failed_integrations'] += 1
        
        # Check EDR connectors
        for name, connector in self.edr_connectors.items():
            try:
                result = connector.test_connection()
                status['edr_xdr'][name] = {
                    'status': 'active' if result['success'] else 'failed',
                    'enabled': connector.enabled,
                    'last_check': datetime.utcnow().isoformat(),
                    'error': result.get('error') if not result['success'] else None
                }
                status['summary']['total_integrations'] += 1
                if result['success']:
                    status['summary']['active_integrations'] += 1
                else:
                    status['summary']['failed_integrations'] += 1
                    
            except Exception as e:
                status['edr_xdr'][name] = {
                    'status': 'error',
                    'enabled': connector.enabled,
                    'last_check': datetime.utcnow().isoformat(),
                    'error': str(e)
                }
                status['summary']['total_integrations'] += 1
                status['summary']['failed_integrations'] += 1
        
        return status
    
    def enrich_iocs_bulk(self, iocs: List[Dict[str, str]], sources: List[str]) -> Dict[str, Any]:
        """Bulk enrich IOCs using specified threat intelligence sources"""
        logger.info("Starting bulk IOC enrichment", 
                   ioc_count=len(iocs), 
                   sources=sources)
        
        results = {
            'success': True,
            'processed': 0,
            'failed': 0,
            'results': [],
            'summary': {
                'total_iocs': len(iocs),
                'sources_used': sources,
                'start_time': datetime.utcnow().isoformat(),
                'end_time': None,
                'duration_seconds': 0
            }
        }
        
        start_time = datetime.utcnow()
        
        try:
            # Filter available sources
            available_sources = [s for s in sources if s in self.threat_intel_connectors]
            
            if not available_sources:
                return {
                    'success': False,
                    'error': 'No available threat intelligence sources configured',
                    'available_sources': list(self.threat_intel_connectors.keys())
                }
            
            # Process IOCs with thread pool for parallel execution
            futures = []
            
            for ioc in iocs:
                for source in available_sources:
                    connector = self.threat_intel_connectors[source]
                    future = self.executor.submit(
                        self._enrich_single_ioc,
                        connector, 
                        ioc['value'], 
                        ioc['type'], 
                        source
                    )
                    futures.append((future, ioc, source))
            
            # Collect results
            ioc_results = {}
            
            for future, ioc, source in futures:
                try:
                    result = future.result(timeout=30)  # 30 second timeout per enrichment
                    
                    ioc_key = f"{ioc['value']}_{ioc['type']}"
                    if ioc_key not in ioc_results:
                        ioc_results[ioc_key] = {
                            'ioc_value': ioc['value'],
                            'ioc_type': ioc['type'],
                            'enrichments': {},
                            'overall_reputation': 'unknown',
                            'risk_score': 0,
                            'enriched_at': datetime.utcnow().isoformat()
                        }
                    
                    if result['success']:
                        ioc_results[ioc_key]['enrichments'][source] = result.get('enrichment', {})
                        results['processed'] += 1
                    else:
                        ioc_results[ioc_key]['enrichments'][source] = {
                            'error': result.get('error', 'Unknown error')
                        }
                        results['failed'] += 1
                        
                except Exception as e:
                    logger.error("Enrichment task failed", 
                               ioc=ioc['value'], 
                               source=source, 
                               error=str(e))
                    results['failed'] += 1
            
            # Calculate overall reputation and risk scores
            for ioc_data in ioc_results.values():
                ioc_data['overall_reputation'] = self._calculate_overall_reputation(ioc_data['enrichments'])
                ioc_data['risk_score'] = self._calculate_risk_score(ioc_data['enrichments'])
            
            results['results'] = list(ioc_results.values())
            
            # Update summary
            end_time = datetime.utcnow()
            results['summary']['end_time'] = end_time.isoformat()
            results['summary']['duration_seconds'] = (end_time - start_time).total_seconds()
            results['summary']['sources_queried'] = available_sources
            
            logger.info("Bulk IOC enrichment completed",
                       processed=results['processed'],
                       failed=results['failed'],
                       duration=results['summary']['duration_seconds'])
            
            return results
            
        except Exception as e:
            logger.error("Bulk IOC enrichment failed", error=str(e))
            results['success'] = False
            results['error'] = str(e)
            return results
    
    def hunt_threats_bulk(self, iocs: List[str], platforms: List[str]) -> Dict[str, Any]:
        """Hunt for threats across multiple EDR/XDR platforms"""
        logger.info("Starting bulk threat hunting", 
                   ioc_count=len(iocs), 
                   platforms=platforms)
        
        results = {
            'success': True,
            'hunted_iocs': len(iocs),
            'platforms_used': [],
            'total_matches': 0,
            'results': [],
            'summary': {
                'start_time': datetime.utcnow().isoformat(),
                'end_time': None,
                'duration_seconds': 0
            }
        }
        
        start_time = datetime.utcnow()
        
        try:
            # Filter available platforms
            available_platforms = [p for p in platforms if p in self.edr_connectors]
            
            if not available_platforms:
                return {
                    'success': False,
                    'error': 'No EDR/XDR platforms configured',
                    'available_platforms': list(self.edr_connectors.keys())
                }
            
            results['platforms_used'] = available_platforms
            
            # Hunt IOCs on each platform
            futures = []
            
            for platform in available_platforms:
                connector = self.edr_connectors[platform]
                future = self.executor.submit(
                    connector.hunt_iocs,
                    iocs
                )
                futures.append((future, platform))
            
            # Collect hunting results
            for future, platform in futures:
                try:
                    result = future.result(timeout=120)  # 2 minute timeout per platform
                    
                    if result['success']:
                        platform_result = {
                            'platform': platform,
                            'status': 'success',
                            'results': result.get('results', {}),
                            'matches_found': sum(
                                r.get('matches_found', 0) 
                                for r in result.get('results', {}).values()
                            ),
                            'hunted_at': datetime.utcnow().isoformat()
                        }
                        results['total_matches'] += platform_result['matches_found']
                    else:
                        platform_result = {
                            'platform': platform,
                            'status': 'failed',
                            'error': result.get('error', 'Unknown error'),
                            'matches_found': 0
                        }
                    
                    results['results'].append(platform_result)
                    
                except Exception as e:
                    logger.error("Hunting task failed", 
                               platform=platform, 
                               error=str(e))
                    results['results'].append({
                        'platform': platform,
                        'status': 'error',
                        'error': str(e),
                        'matches_found': 0
                    })
            
            # Update summary
            end_time = datetime.utcnow()
            results['summary']['end_time'] = end_time.isoformat()
            results['summary']['duration_seconds'] = (end_time - start_time).total_seconds()
            
            logger.info("Bulk threat hunting completed",
                       total_matches=results['total_matches'],
                       platforms_used=len(available_platforms),
                       duration=results['summary']['duration_seconds'])
            
            return results
            
        except Exception as e:
            logger.error("Bulk threat hunting failed", error=str(e))
            results['success'] = False
            results['error'] = str(e)
            return results
    
    def quarantine_files_bulk(self, targets: List[Dict[str, str]]) -> Dict[str, Any]:
        """Quarantine files across multiple endpoints"""
        logger.info("Starting bulk file quarantine", target_count=len(targets))
        
        results = {
            'success': True,
            'total_targets': len(targets),
            'successful_quarantines': 0,
            'failed_quarantines': 0,
            'results': []
        }
        
        try:
            futures = []
            
            # Group targets by platform for efficient processing
            platform_targets = {}
            for target in targets:
                platform = target['platform']
                if platform not in platform_targets:
                    platform_targets[platform] = []
                platform_targets[platform].append(target)
            
            # Execute quarantine operations
            for platform, platform_targets_list in platform_targets.items():
                if platform in self.edr_connectors:
                    connector = self.edr_connectors[platform]
                    
                    for target in platform_targets_list:
                        future = self.executor.submit(
                            connector.quarantine_file,
                            target['endpoint_id'],
                            target['file_hash']
                        )
                        futures.append((future, target, platform))
            
            # Collect results
            for future, target, platform in futures:
                try:
                    result = future.result(timeout=60)
                    
                    if result['success']:
                        results['successful_quarantines'] += 1
                        status = 'success'
                    else:
                        results['failed_quarantines'] += 1
                        status = 'failed'
                    
                    results['results'].append({
                        'endpoint_id': target['endpoint_id'],
                        'file_hash': target['file_hash'],
                        'platform': platform,
                        'status': status,
                        'result': result,
                        'timestamp': datetime.utcnow().isoformat()
                    })
                    
                except Exception as e:
                    results['failed_quarantines'] += 1
                    results['results'].append({
                        'endpoint_id': target['endpoint_id'],
                        'file_hash': target['file_hash'],
                        'platform': platform,
                        'status': 'error',
                        'error': str(e),
                        'timestamp': datetime.utcnow().isoformat()
                    })
            
            logger.info("Bulk quarantine completed",
                       successful=results['successful_quarantines'],
                       failed=results['failed_quarantines'])
            
            return results
            
        except Exception as e:
            logger.error("Bulk quarantine failed", error=str(e))
            results['success'] = False
            results['error'] = str(e)
            return results
    
    def isolate_endpoints_bulk(self, targets: List[Dict[str, str]]) -> Dict[str, Any]:
        """Isolate endpoints across multiple EDR platforms"""
        logger.info("Starting bulk endpoint isolation", target_count=len(targets))
        
        results = {
            'success': True,
            'total_targets': len(targets),
            'successful_isolations': 0,
            'failed_isolations': 0,
            'results': []
        }
        
        try:
            futures = []
            
            for target in targets:
                platform = target['platform']
                if platform in self.edr_connectors:
                    connector = self.edr_connectors[platform]
                    future = self.executor.submit(
                        connector.isolate_endpoint,
                        target['endpoint_id']
                    )
                    futures.append((future, target, platform))
            
            # Collect results
            for future, target, platform in futures:
                try:
                    result = future.result(timeout=60)
                    
                    if result['success']:
                        results['successful_isolations'] += 1
                        status = 'success'
                    else:
                        results['failed_isolations'] += 1
                        status = 'failed'
                    
                    results['results'].append({
                        'endpoint_id': target['endpoint_id'],
                        'platform': platform,
                        'status': status,
                        'result': result,
                        'timestamp': datetime.utcnow().isoformat()
                    })
                    
                except Exception as e:
                    results['failed_isolations'] += 1
                    results['results'].append({
                        'endpoint_id': target['endpoint_id'],
                        'platform': platform,
                        'status': 'error',
                        'error': str(e),
                        'timestamp': datetime.utcnow().isoformat()
                    })
            
            logger.info("Bulk isolation completed",
                       successful=results['successful_isolations'],
                       failed=results['failed_isolations'])
            
            return results
            
        except Exception as e:
            logger.error("Bulk isolation failed", error=str(e))
            results['success'] = False
            results['error'] = str(e)
            return results
    
    def _enrich_single_ioc(self, connector, ioc_value: str, ioc_type: str, source: str) -> Dict[str, Any]:
        """Enrich a single IOC using specified connector"""
        try:
            return connector.enrich_ioc(ioc_value, ioc_type)
        except Exception as e:
            logger.error("Single IOC enrichment failed", 
                        ioc=ioc_value, 
                        source=source, 
                        error=str(e))
            return {'success': False, 'error': str(e)}
    
    def _calculate_overall_reputation(self, enrichments: Dict[str, Any]) -> str:
        """Calculate overall reputation from multiple sources"""
        reputation_scores = {
            'malicious': 3,
            'suspicious': 2,
            'clean': 1,
            'unknown': 0
        }
        
        total_score = 0
        total_sources = 0
        
        for source, data in enrichments.items():
            if isinstance(data, dict) and 'reputation' in data:
                reputation = data['reputation']
                if reputation in reputation_scores:
                    total_score += reputation_scores[reputation]
                    total_sources += 1
        
        if total_sources == 0:
            return 'unknown'
        
        avg_score = total_score / total_sources
        
        if avg_score >= 2.5:
            return 'malicious'
        elif avg_score >= 1.5:
            return 'suspicious'
        elif avg_score >= 0.5:
            return 'clean'
        else:
            return 'unknown'
    
    def _calculate_risk_score(self, enrichments: Dict[str, Any]) -> int:
        """Calculate risk score from 0-100 based on enrichments"""
        risk_score = 0
        
        for source, data in enrichments.items():
            if isinstance(data, dict):
                # VirusTotal detections
                if 'detections' in data:
                    detections = data['detections']
                    if detections.get('total', 0) > 0:
                        malicious_ratio = detections.get('malicious', 0) / detections['total']
                        risk_score += int(malicious_ratio * 40)
                
                # MISP score
                if 'misp_score' in data:
                    risk_score += min(data['misp_score'], 30)
                
                # Reputation-based scoring
                reputation = data.get('reputation', 'unknown')
                if reputation == 'malicious':
                    risk_score += 30
                elif reputation == 'suspicious':
                    risk_score += 15
        
        return min(risk_score, 100)  # Cap at 100
