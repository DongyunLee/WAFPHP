<?php
/**
 * User: Zoa Chou
 * Date: 15/7/30
 */

// 防护系统前缀，避免与其他原程序定义变量冲突
defined('WAF_PREFIX') or define('WAF_PREFIX', 'WAF_');
// 当前系统所在文件路径
defined('WAF_ROOT') or define('WAF_ROOT', __DIR__ . DIRECTORY_SEPARATOR);
// 当前系统配置文件
defined(WAF_PREFIX . 'CONFIG') or define(WAF_PREFIX . 'CONFIG', 'config.default');
// 当前系统开始执行时间
defined(WAF_PREFIX . 'NOW') or define(WAF_PREFIX . 'NOW', microtime(true));
// 当前系统开始执行内存占用大小
defined(WAF_PREFIX . 'RAM') or define(WAF_PREFIX . 'RAM', memory_get_usage());

require_once WAF_ROOT.'vendor/autoload.php';







