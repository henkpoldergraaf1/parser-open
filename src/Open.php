<?php

namespace AbuseIO\Parsers;

use AbuseIO\Jobs\FindContact;
use Carbon\Carbon;
use Ddeboer\DataImport\Reader;
use Mail;
use Log;
use SplFileObject;
use AbuseIO\Models\Incident;

/**
 * Class Abusehub
 * @package AbuseIO\Parsers
 */
class Open extends Parser
{
//    const IP_V_4 = '/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/';
// Grabs IP_V_4 and IP_V_6
    const IP_V_4 = '/(?>(?>([a-f0-9]{1,4})(?>:(?1)){7}|(?!(?:.*[a-f0-9](?>:|$)){8,})((?1)(?>:(?1)){0,6})?::(?2)?)|(?>(?>(?1)(?>:(?1)){5}:|(?!(?:.*[a-f0-9]:){6,})(?3)?::(?>((?1)(?>:(?1)){0,4}):)?)?(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?>\.(?4)){3}))/iD';

    private $messageBody;

    /**
     * Create a new Snel instance
     *
     * @param \PhpMimeMailParser\Parser phpMimeParser object
     * @param array $arfMail array with ARF detected results
     */
    public function __construct($parsedMail, $arfMail)
    {
        // Call the parent constructor to initialize some basics
        parent::__construct($parsedMail, $arfMail, $this);

        $this->messageBody =  $this->parsedMail->getMessageBody('text') ?: $this->parsedMail->getMessageBody('html');
    }

    /**
     * Parse
     *
     * harvest IPv4, IPv6 or Hostname from messageBody
     *
     * @return array    Returns array with failed or success data
     *                  (See parser-common/src/Parser.php) for more info.
     */
    public function parse()
    {
        $this->feedName = 'default';


        if ($this->isKnownFeed() && $this->isEnabledFeed()) {

            foreach ($this->getAllIpsToSendIncidentTo() as $ip) {
                $report = $this->getReport($ip);
                // Sanity check
                if ($this->hasRequiredFields($report) === true) {

                    // incident has all requirements met, filter and add!
                    $report = $this->applyFilters($report);

                    $incident = new Incident();
                    $incident->source = config("{$this->configBase}.parser.name");
                    $incident->source_id = false;
                    $incident->ip = $ip; //$report['Source-IP'];
                    $incident->domain = false;
                    $incident->class = config("{$this->configBase}.feeds.{$this->feedName}.class");
                    $incident->type = config("{$this->configBase}.feeds.{$this->feedName}.type");
                    $incident->timestamp = strtotime($report['event_date'] . ' ' . $report['event_time']);
                    $incident->information = $this->getSaveableVersionForReport($report);

                    $this->incidents[] = $incident;
                }
            }
        } else {
            $this->warningCount++;
        }

        return $this->success();
    }

    private function getSaveableVersionForReport($report)
    {
        $saveableReport = json_encode($report);
        if (json_last_error() === 5) { // JSON_ERROR_UTF8
            $report['message'] = utf8_encode($report['message']);
            $saveableReport = json_encode($report);
        }

        return $saveableReport;
    }

    private function getAllIpsToSendIncidentTo()
    {
        $ipsFound = array_unique(
            array_merge(
                $this->getAllIpsFromMail(),
                $this->getAllIpsFromHostNamesInMail()
            )
        );

        $findContact = new FindContact();

        $ips = [];

        foreach ($ipsFound as $key => $ip) {
            $contact = $findContact->byIP($ip);
            if ($contact->reference != 'UNDEF') {
                $ips[] = $ip;
            }
        }

        Log::warning(print_r($ips, true));

        if (count($ips) === 0) {
            $this->sendEmailBackToSender();
        }


        return $ips;
    }

    private function getEmailAddressFromMail(){
        preg_match_all("/[\._a-zA-Z0-9-]+@[\._a-zA-Z0-9-]+/i", $this->parsedMail->getHeader('from'), $matches);
        return $matches[0];
    }

    private function sendEmailBackToSender()
    {
        Log::info('Cannot find contact info in email, trying to inform the from address');
        $body = $this->messageBody;
        $to = $this->getEmailAddressFromMail();

        if (!filter_var($to, FILTER_VALIDATE_EMAIL)) {
            Log::info('No valid from address found in mail headers '. print_r($to, true));
            return;
        }


        Log::info('found email address'. print_r($to, true));
        $send = Mail::raw('Dear Sir/Madam,

Your abuse report has been marked as invalid. Possible reasons include:
- The IP address is no longer in use (the server has expired or been suspended)
- The IP address you reported does not / no longer belong to our network
- Your e-mail did not contain a (valid) IP address

If the abusive content is still online, please send this report again. Make sure to include an IP address of the server hosting the abusive content.',
            function ($message) use ($to, $body ) {
                $message->from( Config::get('main.notifications.from_address'), 'Abuse.bz Alerter');
                $message->to($to);
                $message->subject('Abuse report has been marked invalid');
                $message->attachData($body, 'received.eml');
            }
        );

        if ($send) {
            Log::info('Send email back to sender was successfull');
        } else {
            Log::info('A problem occured while sending back email to complainer');
        }

    }


    private function getAllIpsFromMail()
    {
        preg_match_all(self::IP_V_4, $this->messageBody, $matches);
        if (array_key_exists(0, $matches) && array_key_exists(0, $matches[0])) {
            return $matches[0];
        }
        return [];
    }

    private function getAllIpsFromHostNamesInMail()
    {
        $matches = $this->getHostNameFromString($this->parsedMail->getMessageBody());
        if ($matches) {
            return $this->convertHostNamesToIps($matches);
        }
        return [];
    }

    public static function getHostNameFromString($str)
    {
        $arr = self::harvestWordsFromString($str);
        $result = [];
        foreach ($arr as $subject) {
            $subject = parse_url(trim($subject), PHP_URL_HOST);

            if ($subject) {
                $result[] = $subject;
            }
        }

        return $result;


//        dd(preg_match_all(self::DOMAIN_NAME, $str));
    }

    private static function harvestWordsFromString($str)
    {
        $readingChars = ['. ', ', ', ': ', '; ', '(', ')', '[', ']'];
        $str = str_replace($readingChars, ' ', $str);

        return explode(' ', $str);
    }


    private function getReport($ip)
    {
        global $report;

        $report = [];
        $report['Source-IP'] = $ip;// $this->getIp();
//        $report['domain'] = $this->getDomain();
        $report['event_date'] = $this->getEventDate();
        $report['event_time'] = $this->getEventTime();
        $report['message'] = $this->messageBody;

        if (!$report['Source-IP']) {
            $report['Source-IP'] = $ip;
        }

        return $report;
    }

    private function getIp()
    {
        preg_match_all(self::IP_V_4, $this->messageBody, $matches);
        if (array_key_exists(0, $matches) && array_key_exists(0, $matches[0])) {
            return $matches[0][0];
        }

        return false;
    }


    private function getEventDate()
    {
        return Carbon::parse($this->parsedMail->getHeader('date'))->format('Y-m-d');
    }

    private function getEventTime()
    {
        return Carbon::parse($this->parsedMail->getHeader('date'))->format('H:i:s');
    }

    private function convertHostNamesToIps($names)
    {
        $result = [];
        foreach ($names as $name) {
            $ip = gethostbyname($name);
            if ($ip !== $name) {
                $result[] = $ip;
            }
        }
        return $result;
    }
}
