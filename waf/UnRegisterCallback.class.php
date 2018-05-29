<?php
/**
 * Name: UnRegisterCallback.class.php-WAFPHP
 * Author: lidongyun@shuwang-tech.com
 * Date: 2018/5/29
 * Time: 15:24
 */

namespace WAFPHP;

/**
 * 注销callback类型的系统调用类，规避PHP无法注销callback问题
 * Class UnRegisterCallback
 * @package WAFPHP
 */
class UnRegisterCallback
{
	/** @var callable 储存的callback */
	private $callback;
	
	/**
	 * 储存callback
	 * UnRegisterCallback constructor.
	 * @param $callback
	 * @throws \WAFPHP\WAFPHPException
	 */
	public function __construct ($callback)
	{
		if ( is_callable($callback) ) {
			$this->callback = $callback;
		} else {
			throw new WAFPHPException("Not a Callback");
		}
	}
	
	/**
	 * @param $callback
	 * @throws \WAFPHP\WAFPHPException
	 */
	public function UnRegisterCallback ($callback)
	{
		$this->__construct($callback);
	}
	
	/**
	 * callback钩子，当钩子被注销后callback失效
	 * @return bool
	 */
	public function register ()
	{
		if ( $this->callback == false ) {
			return false;
		}
		
		// 调用callback
		$callback = $this->callback;
		call_user_func($callback);
		
		return true;
	}
	
	/**
	 * 注销callback钩子
	 * @return bool
	 */
	public function unRegister ()
	{
		$this->callback = false;
		
		return true;
	}
}