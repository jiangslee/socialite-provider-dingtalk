<?php

namespace Jiangslee\SocialiteProviders\Dingtalk;

use SocialiteProviders\Manager\SocialiteWasCalled;

class DingtalkExtendSocialite
{
    /**
     * Register the provider.
     *
     * @param \SocialiteProviders\Manager\SocialiteWasCalled $socialiteWasCalled
     */
    public function handle(SocialiteWasCalled $socialiteWasCalled)
    {
        $socialiteWasCalled->extendSocialite('dingtalk', Provider::class);
    }
}
