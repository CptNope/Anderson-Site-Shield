/* JAT Site Shield: two-factor setup screen. */
( function () {
	'use strict';
	function init() {
		var box = document.getElementById( 'jatss-qr' );
		if ( box && window.qrcode ) {
			var qr = window.qrcode( 0, 'M' );
			qr.addData( box.getAttribute( 'data-uri' ) );
			qr.make();
			box.innerHTML = qr.createSvgTag( { cellSize: 5, margin: 4, scalable: true } );
		}
		var labels = window.jatssTwoFactor || {};
		document.querySelectorAll( '[data-jatss-copy]' ).forEach( function ( btn ) {
			btn.addEventListener( 'click', function () {
				if ( navigator.clipboard ) {
					navigator.clipboard.writeText( btn.getAttribute( 'data-jatss-copy' ) );
				}
				btn.textContent = labels.copied || 'Copied';
			} );
		} );
	}
	if ( document.readyState === 'loading' ) {
		document.addEventListener( 'DOMContentLoaded', init );
	} else {
		init();
	}
}() );
