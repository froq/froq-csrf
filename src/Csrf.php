<?php
/**
 * MIT License <https://opensource.org/licenses/mit>
 *
 * Copyright (c) 2015 Kerem Güneş
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is furnished
 * to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
declare(strict_types=1);

namespace froq\csrf;

/**
 * Csrf.
 * @package froq\csrf
 * @object  froq\csrf\Csrf
 * @author  Kerem Güneş <k-gun@mail.com>
 * @since   3.0
 */
final class Csrf
{
    /**
     * Token.
     * @var string
     */
    private $token;

    /**
     * Constructor.
     * @param string|null $token
     */
    public function __construct(string $token = null)
    {
        $token && $this->setToken($token);
    }

    /**
     * Set token.
     * @param  string $token
     * @return void
     */
    public function setToken(string $token): void
    {
        $this->token = $token;
    }

    /**
     * Get token.
     * @return ?string
     */
    public function getToken(): ?string
    {
        return $this->token;
    }

    /**
     * Validate token.
     * @param  ?string $token
     * @return bool
     * @throws froq\csrf\CsrfException
     */
    public function validateToken(?string $token): bool
    {
        if ($this->token == null) {
            throw new CsrfException('Csrf object has no token, set token first before validation');
        }

        return $token && $token === $this->token;
    }

    /**
     * Validate tokens.
     * @param  ?string $token1
     * @param  ?string $token2
     * @return bool
     */
    public static function validateTokens(?string $token1, ?string $token2): bool
    {
        return $token1 && $token2 && $token1 === $token2;
    }

    /**
     * Generate token.
     * @return string
     */
    public static function generateToken(): string
    {
        return sha1(random_bytes(20)); // sha1(40/2=20)
    }
}
