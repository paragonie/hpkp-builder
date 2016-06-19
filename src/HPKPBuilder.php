<?php
declare(strict_types=1);
namespace ParagonIE\HPKPBuilder;
use ParagonIE\ConstantTime\Base64;
use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\ConstantTime\Binary;
use ParagonIE\ConstantTime\Hex;

/**
 * Class HPKPBuilder
 *
 * Quickly and easily build HTTP Public-Key-Pinning headers for your PHP
 * projects to mitigate the risk of MITM via rogue certificate authorities.
 *
 * @package ParagonIE\HPKPBuilder
 */
class HPKPBuilder
{
    /**
     * @var string
     */
    protected $compiled = '';

    /**
     * @var array
     */
    protected $config = [];

    /**
     * @var bool
     */
    protected $needsCompile = true;

    /**
     * HPKPBuilder constructor
     *.
     * @param array $preloaded
     */
    public function __construct(array $preloaded = [])
    {
        if (!empty($preloaded)) {
            $this->config = $preloaded;
        }
    }

    /**
     * Add a hash directly.
     *
     * @param string $hash
     * @param string $algo
     * @return HPKPBuilder
     */
    public function addHash(string $hash, string $algo = 'sha256'): self
    {
        if (empty($this->config['hashes'])) {
            $this->config['hashes'] = [];
        }
        $hash = $this->coerceBase64($hash, $algo);
        $this->config['hashes'][] = [
            'algo' => $algo,
            'hash' => $hash
        ];
        $this->needsCompile = true;
        return $this;
    }

    /**
     * Compile the CSP header, store it in the protected $compiled property.
     *
     * @return HPKPBuilder
     */
    public function compile(): self
    {
        $includeSubs = $this->config['include-subdomains'] ?? false;
        $hashes = $this->config['hashes'] ?? [];
        $maxAge = $this->config['max-age'] ?? 5184000;
        $reportOnly = $this->config['report-only'] ?? false;
        $reportUri = $this->config['report-uri'] ?? null;
        if (empty($hashes)) {
            // Send nothing.
            $this->compiled = '';
            return $this;
        }

        $header = ($reportOnly && !empty($reportUri))
            ? 'Public-Key-Pins-Report-Only: '
            : 'Public-Key-Pins: ';

        foreach ($hashes as $h) {
            $header .= 'pin-' . $h['algo'] . '=';
            $header .= \json_encode($h['hash']);
            $header .= '; ';
        }
        $header .= 'max-age=' . $maxAge;

        if ($includeSubs) {
            $header .= '; includeSubDomains';
        }
        if ($reportUri) {
            $header .= '; report-uri="' . $reportUri . '"';
        }

        $this->compiled = $header;
        $this->needsCompile = false;
        return $this;
    }

    /**
     * Load configuration from a JSON file.
     *
     * @param string $filename
     * @return HPKPBuilder
     * @throws \Exception
     */
    public static function fromFile(string $filename = ''): self
    {
        if (!file_exists($filename)) {
            throw new \Exception($filename.' does not exist');
        }
        $json = \file_get_contents($filename);
        $array = \json_decode($json, true);
        return new HPKPBuilder($array);
    }

    /**
     * @return string
     */
    public function getHeader(): string
    {
        if ($this->needsCompile) {
            $this->compile();
        }
        return $this->compiled;
    }

    /**
     * @return string
     */
    public function getJSON(): string
    {
        return \json_encode($this->config);
    }

    /**
     * Add the includeSubdomains directive in the HPKP header?
     *
     * @param bool $includeSubs
     * @return HPKPBuilder
     */
    public function includeSubdomains(bool $includeSubs = false): self
    {
        $this->config['include-subdomains'] = $includeSubs;
        $this->needsCompile = true;
        return $this;
    }

    /**
     * Set the max-age parameter of the HPKP header
     *
     * @param int $maxAge
     * @return HPKPBuilder
     */
    public function maxAge(int $maxAge = 5184000): self
    {
        $this->config['max-age'] = $maxAge;
        $this->needsCompile = true;
        return $this;
    }

    /**
     * Send a Report-Only header?
     *
     * @param bool $reportOnly
     * @return HPKPBuilder
     */
    public function reportOnly(bool $reportOnly = false): self
    {
        $this->config['report-only'] = $reportOnly;
        $this->needsCompile = true;
        return $this;
    }

    /**
     * Set the report-uri parameter of the HPKP header
     *
     * @param string $reportURI
     * @return HPKPBuilder
     */
    public function reportUri(string $reportURI): self
    {
        $this->config['report-uri'] = $reportURI;
        $this->needsCompile = true;
        return $this;
    }

    /**
     * Send the HPKP header
     *
     * @return bool
     */
    public function sendHPKPHeader(): bool
    {
        if (\headers_sent()) {
            return false;
        }
        \header($this->getHeader());
        return true;
    }

    /**
     * Coerce a string into base64 format.
     *
     * @param string $hash
     * @param string $algo
     * @return string
     * @throws \Exception
     */
    protected function coerceBase64(string $hash, string $algo = 'sha256'): string
    {
        switch ($algo) {
            case 'sha256':
                $limits = [
                    'raw' => 32,
                    'hex' => 64,
                    'pad_min' => 40,
                    'pad_max' => 44
                ];
                break;
            default:
                throw new \Exception(
                    'Browsers currently only support sha256 public key pins.'
                );
        }

        $len = Binary::safeStrlen($hash);
        if ($len === $limits['hex']) {
            $hash = Base64::encode(Hex::decode($hash));
        } elseif ($len === $limits['raw']) {
            $hash = Base64::encode($hash);
        } elseif ($len > $limits['pad_min'] && $len < $limits['pad_max']) {
            // Padding was stripped!
            $hash .= \str_repeat('=', $len % 4);

            // Base64UrlSsafe encoded.
            if (\strpos($hash, '_') !== false || \strpos($hash, '-') !== false) {
                $hash = Base64UrlSafe::decode($hash);
            } else {
                $hash = Base64::decode($hash);
            }
            $hash = Base64::encode($hash);
        }
        return $hash;
    }
}
