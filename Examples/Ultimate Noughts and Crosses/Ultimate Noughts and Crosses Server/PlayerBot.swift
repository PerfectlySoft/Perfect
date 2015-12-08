//
//  PlayerBot.swift
//  Ultimate Noughts and Crosses
//
//  Created by Kyle Jessup on 2015-11-16.
//  Copyright © 2015 PerfectlySoft. All rights reserved.
//
//	This program is free software: you can redistribute it and/or modify
//	it under the terms of the GNU Affero General Public License as
//	published by the Free Software Foundation, either version 3 of the
//	License, or (at your option) any later version, as supplemented by the
//	Perfect Additional Terms.
//
//	This program is distributed in the hope that it will be useful,
//	but WITHOUT ANY WARRANTY; without even the implied warranty of
//	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//	GNU Affero General Public License, as supplemented by the
//	Perfect Additional Terms, for more details.
//
//	You should have received a copy of the GNU Affero General Public License
//	and the Perfect Additional Terms that immediately follow the terms and
//	conditions of the GNU Affero General Public License along with this
//	program. If not, see <http://www.perfect.org/AGPL_3_0_With_Perfect_Additional_Terms.txt>.
//

import Darwin

class PlayerBotRandom: Player {
	
	init(gameId: Int, type: PieceType) {
		super.init(nick: "Random-Bot", gameId: gameId, type: type)
	}
	
	func move(gameState: GameState) {
		let (_, _, x, y) = gameState.currentPlayer(self.gameId)
		if x != INVALID_ID {
			let boardId = gameState.boardId(gameId, x: x, y: y)
			return self.moveOnBoard(gameState, boardId: boardId)
		}
		// we can move on any board
		// pick an unowned board at random
		var boards = [Int]()
		for x in 0..<3 {
			for y in 0..<3 {
				let boardId = gameState.boardId(self.gameId, x: x, y: y)
				let boardOwner = gameState.boardOwner(boardId)
				if boardOwner == .None {
					boards.append(boardId)
				}
			}
		}
		guard boards.count > 0 else {
			fatalError("It's my turn but there are no valid boards on which to play")
		}
		let rnd = arc4random_uniform(UInt32(boards.count))
		let boardId = boards[Int(rnd)]
		self.moveOnBoard(gameState, boardId: boardId)
	}
	
	private func moveOnBoard(gameState: GameState, boardId: Int) {
		// find a random slot
		var slots = [Int]()
		for x in 0..<3 {
			for y in 0..<3 {
				let slotId = gameState.slotId(boardId, x: x, y: y)
				let slotOwner = gameState.slotOwner(slotId)
				if slotOwner == .None {
					slots.append(slotId)
				}
			}
		}
		guard slots.count > 0 else {
			fatalError("It's my turn but there are no valid slots on which to play")
		}
		let rnd = arc4random_uniform(UInt32(slots.count))
		let slotId = slots[Int(rnd)]
		gameState.setSlotOwner(slotId, type: self.type)
	}
}

