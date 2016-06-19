<?php
declare(strict_types=1);

use \ParagonIE\HPKPBuilder\HPKPBuilder;

class BasicTest extends PHPUnit_Framework_TestCase
{
    protected function getHPKPObject($reportURI)
    {
        $hashes = [
            '1VilPkeVqirlPifk5scbzcTTbMT2clp+Zkyv9VFFasE=',
            '1VilPkeVqirlPifk5scbzcTTbMT2clp-Zkyv9VFFasE',
            'd558a53e4795aa2ae53e27e4e6c71bcdc4d36cc4f6725a7e664caff551456ac1',
            "\xd5\x58\xa5\x3e\x47\x95\xaa\x2a\xe5\x3e\x27\xe4\xe6\xc7\x1b\xcd".
            "\xc4\xd3\x6c\xc4\xf6\x72\x5a\x7e\x66\x4c\xaf\xf5\x51\x45\x6a\xc1"
        ];

        $hpkp = new HPKPBuilder();
        foreach ($hashes as $h) {
            $hpkp->addHash($h);
        }
        $hpkp->reportOnly(true)
            ->reportUri($reportURI)
            ->includeSubdomains(true);
        return $hpkp;
    }

    /**
     * @covers HPKPBuilder::addHash
     * @covers HPKPBuilder::coerceBase64
     * @covers HPKPBuilder::includeSubdomains
     * @covers HPKPBuilder::reportOnly
     * @covers HPKPBuilder::reportUri
     */
    public function testHeaderOutput()
    {
        $reportURI = 'https://f038192cab4afafaacee34d22ed2e1dd.report-uri.io/r/default/hpkp/reportOnly';
        $hpkp = $this->getHPKPObject($reportURI);

        $this->assertSame(
            "Public-Key-Pins-Report-Only: " .
                "pin-sha256=\"1VilPkeVqirlPifk5scbzcTTbMT2clp+Zkyv9VFFasE=\"; " .
                "pin-sha256=\"1VilPkeVqirlPifk5scbzcTTbMT2clp+Zkyv9VFFasE=\"; " .
                "pin-sha256=\"1VilPkeVqirlPifk5scbzcTTbMT2clp+Zkyv9VFFasE=\"; " .
                "pin-sha256=\"1VilPkeVqirlPifk5scbzcTTbMT2clp+Zkyv9VFFasE=\"; " .
                "max-age=5184000; includeSubDomains; " .
                "report-uri=\"" . $reportURI . "\""
            ,
            $hpkp->getHeader()
        );

        $hpkp->reportOnly(false);
        $this->assertSame(
            "Public-Key-Pins: " .
            "pin-sha256=\"1VilPkeVqirlPifk5scbzcTTbMT2clp+Zkyv9VFFasE=\"; " .
            "pin-sha256=\"1VilPkeVqirlPifk5scbzcTTbMT2clp+Zkyv9VFFasE=\"; " .
            "pin-sha256=\"1VilPkeVqirlPifk5scbzcTTbMT2clp+Zkyv9VFFasE=\"; " .
            "pin-sha256=\"1VilPkeVqirlPifk5scbzcTTbMT2clp+Zkyv9VFFasE=\"; " .
            "max-age=5184000; includeSubDomains; " .
            "report-uri=\"" . $reportURI . "\""
            ,
            $hpkp->getHeader()
        );

        $hpkp->reportOnly(true)
            ->reportUri('');
        $this->assertSame(
            "Public-Key-Pins: " .
            "pin-sha256=\"1VilPkeVqirlPifk5scbzcTTbMT2clp+Zkyv9VFFasE=\"; " .
            "pin-sha256=\"1VilPkeVqirlPifk5scbzcTTbMT2clp+Zkyv9VFFasE=\"; " .
            "pin-sha256=\"1VilPkeVqirlPifk5scbzcTTbMT2clp+Zkyv9VFFasE=\"; " .
            "pin-sha256=\"1VilPkeVqirlPifk5scbzcTTbMT2clp+Zkyv9VFFasE=\"; " .
            "max-age=5184000; includeSubDomains"
            ,
            $hpkp->getHeader()
        );

        $hpkp->includeSubdomains(false);

        $this->assertSame(
            "Public-Key-Pins: " .
            "pin-sha256=\"1VilPkeVqirlPifk5scbzcTTbMT2clp+Zkyv9VFFasE=\"; " .
            "pin-sha256=\"1VilPkeVqirlPifk5scbzcTTbMT2clp+Zkyv9VFFasE=\"; " .
            "pin-sha256=\"1VilPkeVqirlPifk5scbzcTTbMT2clp+Zkyv9VFFasE=\"; " .
            "pin-sha256=\"1VilPkeVqirlPifk5scbzcTTbMT2clp+Zkyv9VFFasE=\"; " .
            "max-age=5184000"
            ,
            $hpkp->getHeader()
        );
    }

    /**
     * @covers HPKPBuilder::fromFile
     * @covers HPKPBuilder::getJSON
     */
    public function testLoadSave()
    {
        $reportURI = 'https://f038192cab4afafaacee34d22ed2e1dd.report-uri.io/r/default/hpkp/reportOnly';
        $hpkp = $this->getHPKPObject($reportURI);
        $saved = $hpkp->getJSON();
        if (@\file_put_contents(__DIR__. '/testing.json', $saved) === false) {
            $this->markTestSkipped('Could not save JSON file');
        }
        $hpkp2 = HPKPBuilder::fromFile(__DIR__. '/testing.json');

        $this->assertSame(
            $hpkp->getHeader(),
            $hpkp2->getHeader()
        );
        \unlink(__DIR__ . '/testing.json');
    }
}