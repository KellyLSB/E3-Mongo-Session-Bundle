<?php

namespace Bundles\Session;
use Bundles\Manage\Tile;
use e;

/**
 * Evolution Session Manage
 * @author Nate Ferrero
 */
class Manage {
	
	public $title = 'Sessions';
	
	public function page($path) {
		return 'Sessions';
	}
	
	public function tile() {
		$tile = new Tile('sessions');
		$tile->body .= '<h2>View and manage active sessions, watch activity, and more.</h2>';
		return $tile;
	}
}