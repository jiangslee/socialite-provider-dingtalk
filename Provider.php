<?php

namespace Jiangslee\SocialiteProviders\Dingtalk;

use GuzzleHttp\RequestOptions;
use Laravel\Socialite\Two\InvalidStateException;
use Illuminate\Support\Arr;
use InvalidArgumentException;
use SocialiteProviders\Manager\OAuth2\AbstractProvider;
use SocialiteProviders\Manager\OAuth2\User;
use Symfony\Component\HttpFoundation\Exception\BadRequestException;

class Provider extends AbstractProvider
{
    public const IDENTIFIER = 'Dingtalk';

    // 根据sns临时授权码获取用户信息(已废弃)
    // https://open.dingtalk.com/document/orgapp-server/obtain-the-user-information-based-on-the-sns-temporary-authorization
    protected string $getUserByCodeUrl = 'https://oapi.dingtalk.com/sns/getuserinfo_bycode';

    // 1、构造登录授权页面
    // https://open.dingtalk.com/document/orgapp-server/obtain-identity-credentials
    protected string $authUrl = 'https://login.dingtalk.com/oauth2/auth';

    // 2、获取当前登录用户的授权Token
    // https://open.dingtalk.com/document/orgapp-server/obtain-user-token
    protected string $userAccessTokenUrl = 'https://api.dingtalk.com/v1.0/oauth2/userAccessToken';

    // 3、获取当前登录用户的个人信息
    // https://open.dingtalk.com/document/orgapp-server/dingtalk-retrieve-user-information
    protected string $getUserinfoUrl = 'https:/api.dingtalk.com/v1.0/contact/users/me';

    /**
     * @var string
     */
    private $openId;

    /**
     * User unionid.
     *
     * @var string
     */
    protected $unionId;

    /**
     * get token(openid) with unionid.
     *
     * @var bool
     */
    protected $withUnionId = false;

    /**
     * The scopes being requested.
     *
     * @var array
     */
    protected $scopes = ['openid'];

    /**
     * {@inheritdoc}.
     *
     * @see \Laravel\Socialite\Two\AbstractProvider::getAuthUrl()
     */
    protected function getAuthUrl($state)
    {
        return $this->buildAuthUrlFromBase($this->authUrl, $state);
    }

    /**
     * {@inheritdoc}.
     *f
     * @param  string|null  $state
     * @return array
     */
    protected function getCodeFields($state = null)
    {
        $fields = [
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUrl,
            'scope' => $this->formatScopes($this->getScopes(), $this->scopeSeparator),
            'prompt' => 'consent',
            'response_type' => 'code',
        ];

        if ($this->usesState()) {
            $fields['state'] = $state;
        }

        if ($this->usesPKCE()) {
            $fields['code_challenge'] = $this->getCodeChallenge();
            $fields['code_challenge_method'] = $this->getCodeChallengeMethod();
        }

        return array_merge($fields, $this->parameters);
    }
    /**
     * {@inheritdoc}.
     *
     * @see \Laravel\Socialite\Two\AbstractProvider::getTokenUrl()
     */
    protected function getTokenUrl()
    {
        return $this->userAccessTokenUrl;
    }

    /**
     * @param bool $value
     *
     * @return self
     */
    public function withUnionId($value = true)
    {
        $this->withUnionId = $value;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function user()
    {
        if ($this->user) {
            return $this->user;
        }

        if ($this->hasInvalidState()) {
            throw new InvalidStateException;
        }

        $response = $this->getAccessTokenResponse($this->getCode());

        $this->user = $this->mapUserToObject($this->getUserByToken(
            $token = Arr::get($response, 'accessToken')
        ));

        return $this->user->setToken($token)
                    ->setRefreshToken(Arr::get($response, 'refreshToken'))
                    ->setExpiresIn(Arr::get($response, 'expireIn'))
                    ->setApprovedScopes(explode($this->scopeSeparator, Arr::get($response, 'scope', '')));
    }
    /**
     * {@inheritdoc}.
     *
     * @see \Laravel\Socialite\Two\AbstractProvider::getUserByToken()
     */
    protected function getUserByToken($token)
    {
        $response = $this->getHttpClient()->get($this->getUserinfoUrl, [
            RequestOptions::HEADERS => [
                'X-Acs-Dingtalk-Access-Token' => $token,
            ]
        ]);

        $me = json_decode($this->removeCallback($response->getBody()->getContents()), true);

        $this->openId = $me['openId'];
        $this->unionId = Arr::get($me, 'unionId', '');

        return $me;
    }

    /**
     * {@inheritdoc}.
     *
     * @see \Laravel\Socialite\Two\AbstractProvider::mapUserToObject()
     */
    protected function mapUserToObject(array $user)
    {
        return (new User())->setRaw($user)->map([
            'id'   => $this->openId, 
            'unionid' => $this->unionId, 
            'nickname' => $user['nick'] ?? null,
            'name' => $user['nick'] ?? null,
            'email' => null, 
            'avatar' => $user['avatarUrl'] ?? null,
        ]);
    }


    /**
     * Get the code from the request.
     *
     * @return string
     */
    protected function getCode()
    {
        return $this->request->input('authCode');
    }
    /**
     * {@inheritdoc}.
     *
     * @see \Laravel\Socialite\Two\AbstractProvider::getTokenFields()
     */
    protected function getTokenFields($code)
    {
        return array_merge(parent::getTokenFields($code), [
            'grantType' => 'authorization_code',
            'clientId' => $this->clientId,
            'clientSecret' => $this->clientSecret,
        ]);
    }
    /**
     * {@inheritdoc}.
     *
     * @see \Laravel\Socialite\Two\AbstractProvider::getAccessToken()
     */
    public function getAccessTokenResponse($code)
    {
        $response = $this->getHttpClient()->post($this->getTokenUrl(), [
            RequestOptions::JSON => $this->getTokenFields($code),
        ]);

        return $this->fromJsonBody($response);
    }


    public function getClientId(): ?string
    {
        return $this->getConfig()->get('appid')
            ?? $this->getConfig()->get('appId');
    }

    public function getClientSecret(): ?string
    {
        return $this->getConfig()->get('appsecret')
            ?? $this->getConfig()->get('appSecret')
            ?? $this->getConfig()->get('client_secret');
    }

    protected function createSignature(int $time): string
    {
        return \base64_encode(\hash_hmac('sha256', (string)$time, (string)$this->getClientSecret(), true));
    }


    protected function fromJsonBody($response): array
    {
        $result = \json_decode((string) $response->getBody(), true);

        \is_array($result) || throw new InvalidArgumentException('Decoded the given response payload failed.');

        return $result;
    }

    public function userFromCode(string $code)
    {
        $time = (int)\microtime(true) * 1000;

        $responseInstance = $this->getHttpClient()->post($this->getUserByCodeUrl, [
            RequestOptions::QUERY => [
                'accessKey' => $this->getClientId(),
                'timestamp' => $time,
                'signature' => $this->createSignature($time)
            ],
            RequestOptions::JSON => [
                'tmp_auth_code' => $code
            ]

        ]);

        $response = $this->fromJsonBody($responseInstance);

        if (0 != ($response['errcode'] ?? 1)) {
            throw new BadRequestException((string)$responseInstance->getBody());
        }

        return new User([
            'id' => $response['user_info']['openid'],
            'unionid' => $response['user_info']['unionid'],
            'name' => $response['user_info']['nick'],
            'nickname' => $response['user_info']['nick'],
        ]);
    }

    /**
     * @param mixed $response
     *
     * @return string
     */
    protected function removeCallback($response)
    {
        if (strpos($response, 'callback') !== false) {
            $lpos = strpos($response, '(');
            $rpos = strrpos($response, ')');
            $response = substr($response, $lpos + 1, $rpos - $lpos - 1);
        }

        return $response;
    }
}
