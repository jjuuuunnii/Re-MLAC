package org.dongguk.mlac.dto.type;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum EAttack {
    BENIGN("BENIGN"),
    PORTSCAN("PORTSCAN"),
    RECONNAISSANCE("RECONNAISSANCE"),
    WEB_ATTACK_BRUTE_FORCE("WEB_ATTACK_BRUTE_FORCE"),
    WEB_ATTACK_XSS("WEB_ATTACK_XSS"),
    WEB_ATTACK_SQL_INJECTION("WEB_ATTACK_SQL_INJECTION"),
    HEARTBLEED("HEARTBLEED"),
    EXPLOITS("EXPLOITS"),
    FUZZERS("FUZZERS"),
    FTP_PATATOR("FTP_PATATOR"),
    SSH_PATATOR("SSH_PATATOR"),
    BACKDOOR("BACKDOOR"),
    BOT("BOT"),
    SHELLCODE("SHELLCODE"),
    WORMS("WORMS"),
    INFILTRATION("INFILTRATION"),
    DOS_SLOWHTTPTEST("DOS_SLOWHTTPTEST"),
    DDOS("DDOS"),
    DOS("DOS"),
    DOS_GOLDENEYE("DOS_GOLDENEYE"),
    DOS_HULK("DOS_HULK"),
    DOS_SLOWLORIS("DOS_SLOWLORIS"),
    GENERIC("GENERIC"),
    ANALYSIS("ANALYSIS");
    private final String type;
}