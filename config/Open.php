<?php





return [
    'parser' => [
        // The name of the parser, should match filename without extension (.php)
        'name'       => 'Open',
        // Wether this parser is enabled. If false its config is entirely ignored in the main
        // config tree and will never be called
        'enabled'    => true,
        // Sender mappings with look in the EMAIL FROM header based on a regular expression
        // to match it. If it's a match this parser will be selected
        'sender_map' => [
            '/^((?!(report@abuse\.io)|(reports@reports\.abusehub\.nl)|(nobody@woody\.ch)|(@mailpit\.powerweb\.de)|(@r\.iecc\.com)|(@junkemailfilter\.com)|(abuse-auto@support\.(juno|netzero)\.com)|(@USGOabuse\.net)|(@ip-echelon\.(com|us))|(autogenerated@blocklist\.de)|(dmca@cegtek\.com)|(abuse@clean-mx\.de)|(@copyright-compliance\.com)|(noreply@p2p\.copyright-notice\.com)|(notices@entura-international\.co\.uk)|(abuse-reports@cyscon\.de)|(scomp@aol\.net)|(feedbackloop@(comcastfbl|mailru|yandexfbl)\.senderscore\.net)|(feedbackloop@feedback\.(bluetie\.com|postmaster\.rr\.com|terra\.com))|(feedbackloop@fbl\.(cox\.net|fastmail\.com|hostedemail\.com|apps\.rackspace\.com|synacor\.com|usa\.net|zoho\.com|italiaonline\.net))|(feedback@arf\.mail\.yahoo\.com)|(noreply@google.com)|(@copyright\.ip-echelon\.(com|us))|(takedown-response.*@netcraft\.com)|(monitor-bounce@projecthoneypot\.org)|(autoreports@shadowserver\.org)|(@reports\.spamcop\.net)|(summaries@admin\.spamcop\.net)|(noreply@spamlogin\.com)|(@abuse-reporting\.webiron\.com)).)*$/',
        ],
        // Same as sender mapping, but then based on the EMAIL BODY text.
        'body_map'   => [
        ],
        // The aliases convert the body_map address into a more friendly source name
        // or convert feed names.
        'aliases'    => [

        ]
    ],
    'feeds'  => [
        // There is always a feed, if there is just one then it's 'default' but you can
        // name them as you like, but referring to data sources would be handy. The name
        // is used by the method (COMMON)$this->isKnownFeed() so see if the feed you selected
        // really exists.
        'default' => [
            // Classification for incidents to be when this feed is used
            'class'   => 'DEFAULT',
            // Type for incidents to be when this feed is used
            'type'    => 'ABUSE',
            // Wither this feed is enabled by using (COMMON)$this->isEnabledFeed()
            'enabled' => true,
            // The minimum required fields your info blob should end up with, which will be
            // validated later by using (COMMON)$this->hasRequiredFields($report)
            'fields'  => [
                'Source-IP',
                'event_date',
                'event_time'
            ],
        ],
    ],
];


