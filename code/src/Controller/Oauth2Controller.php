<?php

namespace App\Controller;

use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;

/**
 * Class Oauth2Controller
 * @package App\Controller
 * @Route("/oauth2", name="oauth2")
 */
class Oauth2Controller extends AbstractController
{
    /**
     * @param ClientRegistry $clientRegistry
     * @return RedirectResponse
     * @Route("/connect", name="_connect")
     */
    public function connectAction(ClientRegistry $clientRegistry)
    {
        return $clientRegistry->getClient('oauth2_server')->redirect([], []);
    }

    /**
     * @param Request $request
     * @param ClientRegistry $clientRegistry
     * @Route("/check", name="_check")
     */
    public function checkAction(Request $request, ClientRegistry $clientRegistry)
    {
        $accessToken = $clientRegistry->getClient('oauth2_server')->getAccessToken()->getToken();
        return $this->render('oauth2/check.html.twig', [
            'accessToken' => $accessToken,
        ]);
    }
}
