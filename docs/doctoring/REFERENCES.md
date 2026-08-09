# Authoritative standards and research references

Status: **PRESENT-CURRENT** as of 2026-08-09 for the product documentation baseline. This index distinguishes current final specifications from drafts and does not itself establish certification or conformance.

## Normative and primary technical references

AICPA & CIMA. (2023). *2017 Trust Services Criteria for security, availability, processing integrity, confidentiality, and privacy (with revised points of focus—2022).* Association of International Certified Professional Accountants. https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022

National Institute of Standards and Technology. (2026). *NIST Cybersecurity Supply Chain Risk Management: Due Diligence Assessment Quick-Start Guide* (NIST SP 1326). https://doi.org/10.6028/NIST.SP.1326

Fielding, R. T., Nottingham, M., & Reschke, J. (2022). *HTTP semantics* (RFC 9110). RFC Editor. https://doi.org/10.17487/RFC9110

KISA. (n.d.). *클라우드 보안인증제(CSAP).* 한국인터넷진흥원 정보보호 및 개인정보보호관리체계 인증 포털. Retrieved August 9, 2026, from https://isms-p.kisa.or.kr/

National Institute of Standards and Technology. (2022). *Secure Software Development Framework (SSDF) version 1.1: Recommendations for mitigating the risk of software vulnerabilities* (NIST SP 800-218). U.S. Department of Commerce. https://doi.org/10.6028/NIST.SP.800-218

National Institute of Standards and Technology. (2024). *Secure software development practices for generative AI and dual-use foundation models: An SSDF community profile* (NIST SP 800-218A). U.S. Department of Commerce. https://doi.org/10.6028/NIST.SP.800-218A

National Institute of Standards and Technology. (2025). *Secure Software Development Framework (SSDF) version 1.2: Recommendations for mitigating the risk of software vulnerabilities* (NIST SP 800-218 Rev. 1, Initial Public Draft). U.S. Department of Commerce. https://doi.org/10.6028/NIST.SP.800-218r1.ipd

Nottingham, M., & Thomson, M. (2024). *Building protocols with HTTP* (RFC 9205). RFC Editor. https://doi.org/10.17487/RFC9205

OWASP Foundation. (2025). *OWASP Application Security Verification Standard (ASVS) 5.0.0.* https://owasp.org/www-project-application-security-verification-standard/

OWASP Foundation. (n.d.). *Server-side request forgery prevention cheat sheet.* OWASP Cheat Sheet Series. Retrieved August 9, 2026, from https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

SLSA Community. (2025). *SLSA specification version 1.2.* https://slsa.dev/spec/v1.2/

## Status notes used by compliance traceability

- **NIST SP 1326 is final.** NIST released the final ICT supplier due-diligence Quick-Start Guide on July 8, 2026, superseding the 2024 draft. Its due-diligence factors include foreign ownership/control/influence, provenance, resilience, foundational cyber practices, and supply-chain tiers. EgressWeave can provide product evidence relevant to some of those questions but does not perform a complete supplier assessment.
- **NIST SP 800-218 / SSDF 1.1 is the current final core SSDF publication.** NIST's publication list identifies SP 800-218 Rev. 1 / SSDF 1.2 as a Draft released December 17, 2025. Draft SSDF material is informative future direction until NIST publishes a final revision.
- **NIST SP 800-218A is final.** It augments SSDF 1.1 for generative AI and dual-use foundation model development. EgressWeave uses this only where autonomous/model-backed engineering boundaries are relevant.
- **OWASP ASVS 5.0.0 is released.** EgressWeave uses it as application-security verification guidance but does not claim all host-application ASVS requirements are implemented by a transport library.
- **SLSA v1.2 is the current Approved specification.** It includes Build and Source tracks. EgressWeave may produce or consume supply-chain evidence without claiming a SLSA level unless every requirement for the stated track and level is independently verified.
- **Trust Services Criteria are control criteria, not a product badge.** A SOC 2 report depends on the complete scoped service organization's control system and an attestation engagement; EgressWeave can contribute technical evidence only.
- **CSAP is a certification program for a defined cloud-service scope.** A Python library by itself is not a CSAP-certified service. Hosts pursuing Korean public-sector cloud certification must satisfy the complete applicable program requirements and assessment scope.

## EgressWeave-specific protocol doctoring

More focused source notes live under [`../research/`](../research/README.md). Those notes connect protocol/security decisions to specific runtime controls and should cite primary standards where possible. This central file provides the commercial documentation spine and does not replace topic-specific analysis.

Key governed topics include:

- exact origin/authority semantics under RFC 9110;
- HTTP/1.1 framing and body semantics under RFC 9112 where cited by topic-specific notes;
- DNS-rebinding and SSRF prevention;
- IDNA/Unicode hostname normalization;
- bounded request/response resource consumption;
- TLS identity and mutual-TLS configuration;
- deterministic release evidence, SBOM and provenance;
- supplier/acquisition due-diligence evidence boundaries; and
- exact-head review/security/release evidence.

## Citation policy

Material protocol, security, compliance, interoperability or supply-chain decisions should prefer current final standards and official primary documentation. Drafts must be labelled as drafts. Peer-reviewed primary research should be used where a question is empirical rather than normative.

Repository documentation must not claim SOC 2, CSAP, SLSA level, NIST conformance, OWASP certification, supplier approval, or any other assessment result without the corresponding scoped evidence and external or program-specific requirements.
