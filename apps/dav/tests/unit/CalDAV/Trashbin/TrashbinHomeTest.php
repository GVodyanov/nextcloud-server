<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
namespace OCA\DAV\Tests\unit\CalDAV\Trashbin;

use OCA\DAV\CalDAV\CalDavBackend;
use OCA\DAV\CalDAV\Trashbin\TrashbinHome;
use PHPUnit\Framework\MockObject\MockObject;
use Test\TestCase;

class TrashbinHomeTest extends TestCase {
	private CalDavBackend&MockObject $backend;
	private TrashbinHome $trashbinHome;

	protected function setUp(): void {
		parent::setUp();

		$this->backend = $this->createMock(CalDavBackend::class);
		$this->trashbinHome = new TrashbinHome(
			$this->backend,
			['uri' => 'principals/users/alice'],
		);
	}

	public function testGetOwner(): void {
		$this->assertSame('principals/users/alice', $this->trashbinHome->getOwner());
	}

	public function testGetAclGrantsOwnerAllPrivileges(): void {
		$acl = $this->trashbinHome->getACL();

		$principals = array_column($acl, 'principal');
		$this->assertContains('principals/users/alice', $principals);

		foreach ($acl as $entry) {
			if ($entry['principal'] === 'principals/users/alice') {
				$this->assertSame('{DAV:}all', $entry['privilege']);
				$this->assertTrue($entry['protected']);
				return;
			}
		}
		$this->fail('ACL entry for owner not found');
	}

	/**
	 * Calendar-proxy-write delegates must receive {DAV:}read on the trashbin
	 * so that a depth-1 PROPFIND on the delegated calendar home succeeds.
	 * They must NOT receive write/all privileges so they cannot restore or
	 * permanently delete trashbin contents.
	 */
	public function testGetAclGrantsProxyWriteReadOnly(): void {
		$acl = $this->trashbinHome->getACL();

		$principals = array_column($acl, 'principal');
		$this->assertContains('principals/users/alice/calendar-proxy-write', $principals);

		foreach ($acl as $entry) {
			if ($entry['principal'] === 'principals/users/alice/calendar-proxy-write') {
				$this->assertSame('{DAV:}read', $entry['privilege']);
				$this->assertTrue($entry['protected']);
				return;
			}
		}
		$this->fail('ACL entry for calendar-proxy-write not found');
	}

	/**
	 * Calendar-proxy-read delegates must also receive {DAV:}read on the trashbin
	 * for the same listing reason, without any write access.
	 */
	public function testGetAclGrantsProxyReadReadOnly(): void {
		$acl = $this->trashbinHome->getACL();

		$principals = array_column($acl, 'principal');
		$this->assertContains('principals/users/alice/calendar-proxy-read', $principals);

		foreach ($acl as $entry) {
			if ($entry['principal'] === 'principals/users/alice/calendar-proxy-read') {
				$this->assertSame('{DAV:}read', $entry['privilege']);
				$this->assertTrue($entry['protected']);
				return;
			}
		}
		$this->fail('ACL entry for calendar-proxy-read not found');
	}

	public function testGetAclHasExactlyThreeEntries(): void {
		$acl = $this->trashbinHome->getACL();

		$this->assertCount(3, $acl, 'Expected exactly three ACL entries: owner, proxy-write, proxy-read');
	}
}
