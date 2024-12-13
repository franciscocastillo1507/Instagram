<?php

namespace SocialiteProviders\Instagram;

use GuzzleHttp\RequestOptions;
use SocialiteProviders\Manager\OAuth2\AbstractProvider;
use SocialiteProviders\Manager\OAuth2\User;

class Provider extends AbstractProvider
{
    public const IDENTIFIER = 'INSTAGRAM';

    protected $scopeSeparator = ' ';

    /**
     * The user fields being requested.
     *
     * @var array
     */
    protected $fields = ['account_type', 'id', 'username', 'media_count'];

    protected $scopes = ['instagram_business_basic'];


    // Store custom parameters
    protected $customParameters = [];
    /**
     * Set the custom parameters for the request.
     *
     * @param  array  $parameters
     * @return $this
     */
    public function with(array $parameters)
    {
        $this->customParameters = $parameters;
        return $this;
    }

    protected function getAuthUrl($state): string
    {
        // Build the base URL for Instagram OAuth
        $url = $this->buildAuthUrlFromBase('https://api.instagram.com/oauth/authorize', $state);
        
        // Append custom parameters to the URL
        if (!empty($this->customParameters)) {
            $url .= '&' . http_build_query($this->customParameters);
        }

        return $url;
    }

    protected function getTokenUrl(): string
    {
        return 'https://api.instagram.com/oauth/access_token';
    }

    /**
     * {@inheritdoc}
     */
    protected function getUserByToken($token)
    {
        $queryParameters = [
            'access_token' => $token,
            'fields'       => implode(',', $this->fields),
        ];

        if (! empty($this->clientSecret)) {
            $queryParameters['appsecret_proof'] = hash_hmac('sha256', $token, $this->clientSecret);
        }

        $response = $this->getHttpClient()->get('https://graph.instagram.com/me', [
            RequestOptions::HEADERS => [
                'Accept' => 'application/json',
            ],
            RequestOptions::QUERY => $queryParameters,
        ]);

        return json_decode((string) $response->getBody(), true);
    }

    /**
     * {@inheritdoc}
     */
    protected function mapUserToObject(array $user)
    {
        return (new User)->setRaw($user)->map([
            'id'            => $user['id'],
            'name'          => $user['username'],
            'account_type'  => $user['account_type'],
            'media_count'   => $user['media_count'] ?? null,
        ]);
    }

    protected function getAccessToken($code)
    {
        $response = $this->getHttpClient()->post($this->getTokenUrl(), [
            RequestOptions::FORM_PARAMS => $this->getTokenFields($code),
        ]);

        $body = json_decode((string) $response->getBody(), true);
        
        $this->credentialsResponseBody = $body;

        return $this->parseAccessToken($body);
    }

    protected function getLongLivedAccessToken(string $shortLivedToken): array
    {
        $response = $this->getHttpClient()->get('https://graph.instagram.com/access_token', [
            RequestOptions::QUERY => [
                'grant_type'    => 'ig_exchange_token',
                'client_secret' => $this->clientSecret,
                'access_token'  => $shortLivedToken,
            ],
        ]);
    
        $body = json_decode((string) $response->getBody(), true);
    
        if (isset($body['access_token'])) {
            return $body;
        }
    
        throw new \Exception('Unable to fetch long-lived access token: ' . ($body['error']['message'] ?? 'Unknown error'));
    }
    
    public function fetchUserByToken($token)
    {
        return $this->getUserByToken($token);
    }


    public function getTokenInstagram($code)
    {
        return $this->getAccessToken($code);
    }

    public function fetchLongLivedAccessToken(string $shortLivedToken): array
    {
        return $this->getLongLivedAccessToken($shortLivedToken);
    }
}
